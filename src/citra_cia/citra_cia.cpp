// Copyright 2026 Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the misc/licenses/gplv2.txt file included.

// azahar-cia: headless CIA management built on the emulator's own container, key and NCCH code.
//
//   azahar-cia [--user-dir DIR] verify  <in.cia>
//   azahar-cia [--user-dir DIR] decrypt <in.cia> <out.cia>
//   azahar-cia [--user-dir DIR] install <in.cia>
//
// Keys are never bundled: they are read from <user-dir>/sysdata (keys.txt, seeddb.bin). When a
// required key is absent the tool exits with status 3 and names the file and the entry to supply.
// Results are one JSON document on stdout; emulator logs go to stderr.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/sha.h>

#include "common/common_paths.h"
#include "common/file_util.h"
#include "common/logging/backend.h"
#include "common/logging/log.h"
#include "core/file_sys/cia_container.h"
#include "core/file_sys/seed_db.h"
#include "core/hle/service/am/am.h"
#include "core/hw/aes/key.h"
#include "core/loader/loader.h"

namespace fs = std::filesystem;

namespace {

constexpr int ExitOk = 0;
constexpr int ExitFailure = 1;
constexpr int ExitUsage = 2;
constexpr int ExitMissingKeys = 3;

constexpr std::size_t IoChunk = 0x100000;
constexpr std::size_t TmdBodySize = 0x9C4;
constexpr std::size_t TmdContentCountOffset = 0x9E;
constexpr std::size_t TmdInfoHashOffset = 0xA4;
constexpr std::size_t TmdInfoOffset = 0xC4;
constexpr std::size_t TmdInfoSize = 0x24;
constexpr std::size_t TmdInfoCount = 64;
constexpr std::size_t TmdChunkSize = 0x30;
constexpr u16 ContentEncryptedFlag = 0x1;

using Hash = std::array<u8, 32>;
using Key = std::array<u8, 16>;

std::string JsonEscape(const std::string& value) {
    std::string out;
    for (const unsigned char c : value) {
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (c < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            } else {
                out += static_cast<char>(c);
            }
        }
    }
    return out;
}

std::string Hex(const u8* data, std::size_t size) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    for (std::size_t i = 0; i < size; ++i) {
        out += digits[data[i] >> 4];
        out += digits[data[i] & 15];
    }
    return out;
}

std::string TitleIdHex(u64 id) {
    char buf[20];
    std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(id));
    return buf;
}

u16 Be16(const u8* p) {
    return static_cast<u16>((p[0] << 8) | p[1]);
}

u32 Be32(const u8* p) {
    return (static_cast<u32>(p[0]) << 24) | (static_cast<u32>(p[1]) << 16) |
           (static_cast<u32>(p[2]) << 8) | p[3];
}

struct Need {
    std::string file;
    std::string entry;
    std::string why;
};

struct Failure {
    int code;
    std::string error;
    std::string message;
    std::vector<Need> missing;
};

int Report(const Failure& failure) {
    std::ostringstream out;
    out << "{\"ok\":false,\"error\":\"" << JsonEscape(failure.error) << "\",\"message\":\""
        << JsonEscape(failure.message) << "\"";
    if (!failure.missing.empty()) {
        out << ",\"missing\":[";
        for (std::size_t i = 0; i < failure.missing.size(); ++i) {
            const Need& need = failure.missing[i];
            out << (i ? "," : "") << "{\"file\":\"" << JsonEscape(need.file) << "\",\"entry\":\""
                << JsonEscape(need.entry) << "\",\"needed_for\":\"" << JsonEscape(need.why)
                << "\"}";
        }
        out << "]";
    }
    out << "}\n";
    std::cout << out.str();
    for (const Need& need : failure.missing) {
        std::cerr << "missing key: " << need.file << " -> " << need.entry << " (" << need.why
                  << ")\n";
    }
    if (failure.missing.empty()) {
        std::cerr << failure.message << "\n";
    }
    return failure.code;
}

Failure MissingKeys(std::vector<Need> missing) {
    return {ExitMissingKeys, "missing-keys",
            "required key material is absent from the azahar user directory", std::move(missing)};
}

/// Names defined in the [AES] section of sysdata/keys.txt (values are never read here).
std::set<std::string> KeyNames() {
    std::set<std::string> names;
    std::ifstream file(FileUtil::GetUserPath(FileUtil::UserPath::SysDataDir) + KEYS_FILE);
    std::string line;
    std::string mode;
    while (std::getline(file, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) {
            line.pop_back();
        }
        if (line.empty() || line[0] == '#') {
            continue;
        }
        if (line[0] == ':') {
            mode = line.substr(1);
            continue;
        }
        const auto eq = line.find('=');
        if (mode == "AES" && eq != std::string::npos && eq + 1 < line.size()) {
            names.insert(line.substr(0, eq));
        }
    }
    return names;
}

std::string SlotKeyX(std::size_t slot) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "slot0x%zXKeyX", slot);
    return buf;
}

class Cia {
public:
    explicit Cia(std::string path_) : path(std::move(path_)) {}

    std::optional<Failure> Open() {
        if (!FileUtil::Exists(path)) {
            return Failure{ExitFailure, "not-found", "file not found: " + path, {}};
        }
        FileUtil::IOFile file(path, "rb");
        if (!file.IsOpen()) {
            return Failure{ExitFailure, "open-failed", "cannot open: " + path, {}};
        }
        if (FileUtil::Z3DSReadIOFile::GetUnderlyingFileMagic(&file).has_value()) {
            return Failure{ExitFailure, "compressed",
                           "compressed (zcia) files are not handled, decompress first", {}};
        }
        file.Seek(0, SEEK_SET);
        if (container.Load(&file) != Loader::ResultStatus::Success) {
            return Failure{ExitFailure, "invalid-cia", "not a valid CIA: " + path, {}};
        }
        return std::nullopt;
    }

    const FileSys::TitleMetadata& Tmd() const {
        return container.GetTitleMetadata();
    }
    bool Present(std::size_t i) {
        return container.GetHeader()->IsContentPresent(i);
    }
    bool ContentEncrypted(std::size_t i) const {
        return (Tmd().GetContentTypeByIndex(i) & ContentEncryptedFlag) != 0;
    }
    bool AnyContentEncrypted() {
        for (std::size_t i = 0; i < Tmd().GetContentCount(); ++i) {
            if (Present(i) && ContentEncrypted(i)) {
                return true;
            }
        }
        return false;
    }

    /// Streams the content with the content-level AES-CBC layer removed.
    bool Stream(std::size_t i, const std::optional<Key>& key,
                const std::function<void(const u8*, std::size_t)>& sink,
                std::size_t limit = SIZE_MAX) {
        std::ifstream file(path, std::ios::binary);
        if (!file) {
            return false;
        }
        file.seekg(static_cast<std::streamoff>(container.GetContentOffset(i)));
        u64 remaining = std::min<u64>(container.GetContentSize(i), limit);
        std::unique_ptr<CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption> cbc;
        if (ContentEncrypted(i)) {
            if (!key) {
                return false;
            }
            const auto iv = Tmd().GetContentCTRByIndex(i);
            cbc = std::make_unique<CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption>(
                key->data(), key->size(), iv.data());
        }
        std::vector<u8> buffer(IoChunk);
        while (remaining) {
            std::size_t want = static_cast<std::size_t>(std::min<u64>(remaining, buffer.size()));
            file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(want));
            if (static_cast<std::size_t>(file.gcount()) != want) {
                return false;
            }
            const std::size_t got = want;
            if (cbc) {
                const std::size_t whole = want & ~static_cast<std::size_t>(15);
                if (whole != want && remaining != want) {
                    return false;
                }
                cbc->ProcessData(buffer.data(), buffer.data(), whole);
            }
            sink(buffer.data(), got);
            remaining -= got;
        }
        return true;
    }

    std::string path;
    FileSys::CIAContainer container;
};

/// NCCH flags relevant to the crypto layer, read from the first 0x200 bytes of a content.
struct NcchProbe {
    bool is_ncch = false;
    bool encrypted = false;
    bool fixed_key = false;
    bool seed = false;
    u8 secondary_slot = 0;
    u64 program_id = 0;
};

NcchProbe ProbeNcch(const std::vector<u8>& head) {
    NcchProbe probe;
    if (head.size() < 0x200 || std::memcmp(head.data() + 0x100, "NCCH", 4) != 0) {
        return probe;
    }
    probe.is_ncch = true;
    const u8 flags7 = head[0x18F];
    probe.fixed_key = (flags7 & 0x1) != 0;
    probe.encrypted = (flags7 & 0x4) == 0;
    probe.seed = (flags7 & 0x20) != 0;
    probe.secondary_slot = head[0x18B];
    for (int i = 7; i >= 0; --i) {
        probe.program_id = (probe.program_id << 8) | head[0x118 + i];
    }
    return probe;
}

struct Analysis {
    std::optional<Key> title_key;
    std::vector<Need> missing;
    bool content_layer_encrypted = false;
    bool ncch_layer_encrypted = false;
};

/// Works out which keys the CIA needs and whether the installed key store provides them.
Analysis Analyze(Cia& cia) {
    Analysis result;
    const auto names = KeyNames();
    const auto have = [&](const std::string& name) { return names.count(name) != 0; };
    const std::string keys_file = std::string("sysdata/") + KEYS_FILE;
    std::set<std::string> reported;
    const auto need = [&](const std::string& file, const std::string& entry,
                          const std::string& why) {
        if (reported.insert(file + "|" + entry).second) {
            result.missing.push_back({file, entry, why});
        }
    };

    HW::AES::InitKeys();
    result.content_layer_encrypted = cia.AnyContentEncrypted();
    if (result.content_layer_encrypted) {
        char common[16];
        const u8 index = cia.container.GetTicket().GetCommonKeyIndex();
        std::snprintf(common, sizeof(common), "common%u", index);
        const std::string why = "ticket title key (content layer)";
        if (!have(SlotKeyX(HW::AES::KeySlotID::TicketCommonKey))) {
            need(keys_file, SlotKeyX(HW::AES::KeySlotID::TicketCommonKey), why);
        }
        if (!have(common)) {
            need(keys_file, common, why);
        }
        if (!have("generatorConstant")) {
            need(keys_file, "generatorConstant", why);
        }
        if (result.missing.empty()) {
            result.title_key = cia.container.GetTicket().GetTitleKey();
            if (!result.title_key) {
                need(keys_file, common, why);
            }
        }
        if (!result.title_key) {
            return result;
        }
    }

    for (std::size_t i = 0; i < cia.Tmd().GetContentCount(); ++i) {
        if (!cia.Present(i)) {
            continue;
        }
        std::vector<u8> head;
        cia.Stream(
            i, result.title_key,
            [&](const u8* data, std::size_t size) {
                head.insert(head.end(), data, data + std::min<std::size_t>(size, 0x200 - head.size()));
            },
            0x200);
        const NcchProbe probe = ProbeNcch(head);
        if (!probe.is_ncch || !probe.encrypted) {
            continue;
        }
        result.ncch_layer_encrypted = true;
        if (probe.fixed_key) {
            continue;
        }
        const std::string why = "NCCH decryption of content " + std::to_string(i);
        const auto require_slot = [&](std::size_t slot) {
            if (!have(SlotKeyX(slot))) {
                need(keys_file, SlotKeyX(slot), why);
            }
        };
        require_slot(HW::AES::KeySlotID::NCCHSecure1);
        switch (probe.secondary_slot) {
        case 1:
            require_slot(HW::AES::KeySlotID::NCCHSecure2);
            break;
        case 10:
            require_slot(HW::AES::KeySlotID::NCCHSecure3);
            break;
        case 11:
            require_slot(HW::AES::KeySlotID::NCCHSecure4);
            break;
        default:
            break;
        }
        if (!have("generatorConstant")) {
            need(keys_file, "generatorConstant", why);
        }
        if (probe.seed && !FileSys::GetSeed(probe.program_id).has_value()) {
            need("sysdata/seeddb.bin", "seed for program " + TitleIdHex(probe.program_id), why);
        }
    }
    return result;
}

Hash Sha256(const u8* data, std::size_t size) {
    Hash hash{};
    CryptoPP::SHA256().CalculateDigest(hash.data(), data, size);
    return hash;
}

bool Sha256File(const std::string& path, Hash& hash, u64& size) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }
    CryptoPP::SHA256 sha;
    std::vector<u8> buffer(IoChunk);
    size = 0;
    while (file) {
        file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        const auto got = static_cast<std::size_t>(file.gcount());
        sha.Update(buffer.data(), got);
        size += got;
    }
    sha.Final(hash.data());
    return true;
}

/// Offset of the TMD body (after the signature and its padding), or 0 when the type is unknown.
std::size_t TmdBodyOffset(const std::vector<u8>& tmd) {
    if (tmd.size() < 4) {
        return 0;
    }
    switch (Be32(tmd.data())) {
    case 0x10000:
    case 0x10003:
        return 0x240;
    case 0x10001:
    case 0x10004:
        return 0x140;
    case 0x10002:
    case 0x10005:
        return 0x80;
    default:
        return 0;
    }
}

/// Clears the encrypted flag, stores the new content hashes and rebuilds both hash levels. The
/// signature is left as is: it no longer validates, which is the nature of a decrypted CIA.
bool PatchTmd(std::vector<u8>& tmd, const std::vector<std::optional<Hash>>& hashes) {
    const std::size_t body = TmdBodyOffset(tmd);
    if (!body || tmd.size() < body + TmdBodySize) {
        return false;
    }
    const std::size_t count = Be16(tmd.data() + body + TmdContentCountOffset);
    const std::size_t chunks = body + TmdBodySize;
    if (tmd.size() < chunks + count * TmdChunkSize || hashes.size() < count) {
        return false;
    }
    for (std::size_t i = 0; i < count; ++i) {
        u8* chunk = tmd.data() + chunks + i * TmdChunkSize;
        u16 type = Be16(chunk + 6);
        type = static_cast<u16>(type & ~ContentEncryptedFlag);
        chunk[6] = static_cast<u8>(type >> 8);
        chunk[7] = static_cast<u8>(type);
        if (hashes[i]) {
            std::memcpy(chunk + 0x10, hashes[i]->data(), hashes[i]->size());
        }
    }
    for (std::size_t k = 0; k < TmdInfoCount; ++k) {
        u8* info = tmd.data() + body + TmdInfoOffset + k * TmdInfoSize;
        const std::size_t first = Be16(info);
        const std::size_t span = Be16(info + 2);
        if (!span) {
            continue;
        }
        if (first + span > count) {
            return false;
        }
        const Hash hash = Sha256(tmd.data() + chunks + first * TmdChunkSize, span * TmdChunkSize);
        std::memcpy(info + 4, hash.data(), hash.size());
    }
    const Hash top = Sha256(tmd.data() + body + TmdInfoOffset, TmdInfoCount * TmdInfoSize);
    std::memcpy(tmd.data() + body + TmdInfoHashOffset, top.data(), top.size());
    return true;
}

bool CopyFile(const std::string& from, const std::string& to) {
    std::ifstream in(from, std::ios::binary);
    std::ofstream out(to, std::ios::binary | std::ios::trunc);
    if (!in || !out) {
        return false;
    }
    std::vector<char> buffer(IoChunk);
    while (in) {
        in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        out.write(buffer.data(), in.gcount());
    }
    return static_cast<bool>(out);
}

std::string ContentSummary(Cia& cia) {
    std::ostringstream out;
    const auto& tmd = cia.Tmd();
    out << "\"title_id\":\"" << TitleIdHex(tmd.GetTitleID()) << "\",\"version\":"
        << tmd.GetTitleVersion() << ",\"content_count\":" << tmd.GetContentCount();
    return out.str();
}

int Verify(const std::string& path) {
    Cia cia(path);
    if (auto failure = cia.Open()) {
        return Report(*failure);
    }
    Analysis analysis = Analyze(cia);
    if (analysis.content_layer_encrypted && !analysis.title_key) {
        return Report(MissingKeys(analysis.missing));
    }
    // Chunk hashes live in the raw TMD.
    FileUtil::IOFile file(path, "rb");
    std::vector<u8> tmd(cia.container.GetTitleMetadataSize());
    file.Seek(static_cast<s64>(cia.container.GetTitleMetadataOffset()), SEEK_SET);
    if (file.ReadBytes(tmd.data(), tmd.size()) != tmd.size()) {
        return Report({ExitFailure, "read-failed", "cannot read the TMD", {}});
    }
    const std::size_t chunks = TmdBodyOffset(tmd) + TmdBodySize;
    std::ostringstream out;
    bool all_ok = true;
    out << "{\"ok\":";
    std::ostringstream items;
    for (std::size_t i = 0; i < cia.Tmd().GetContentCount(); ++i) {
        if (!cia.Present(i)) {
            continue;
        }
        CryptoPP::SHA256 sha;
        u64 size = 0;
        const bool read = cia.Stream(i, analysis.title_key, [&](const u8* data, std::size_t n) {
            sha.Update(data, n);
            size += n;
        });
        Hash hash{};
        sha.Final(hash.data());
        const u8* expected = tmd.data() + chunks + i * TmdChunkSize + 0x10;
        const bool match = read && std::memcmp(hash.data(), expected, 32) == 0 &&
                           size == cia.Tmd().GetContentSizeByIndex(i);
        all_ok = all_ok && match;
        items << (items.tellp() > 0 ? "," : "") << "{\"index\":" << i << ",\"size\":" << size
              << ",\"match\":" << (match ? "true" : "false") << "}";
    }
    out << (all_ok ? "true" : "false") << "," << ContentSummary(cia)
        << ",\"content_layer_encrypted\":" << (analysis.content_layer_encrypted ? "true" : "false")
        << ",\"ncch_layer_encrypted\":" << (analysis.ncch_layer_encrypted ? "true" : "false")
        << ",\"contents\":[" << items.str() << "]}\n";
    std::cout << out.str();
    return all_ok ? ExitOk : ExitFailure;
}

struct Cleanup {
    std::vector<std::string> paths;
    ~Cleanup() {
        std::error_code ec;
        for (const auto& path : paths) {
            fs::remove(path, ec);
        }
    }
};

/// Writes a copy of the CIA with the content layer and the NCCH layer removed.
std::optional<Failure> DecryptCia(Cia& cia, const Analysis& analysis, const std::string& out_path,
                                  bool& removed_layers) {
    removed_layers = analysis.content_layer_encrypted || analysis.ncch_layer_encrypted;
    if (!CopyFile(cia.path, out_path)) {
        return Failure{ExitFailure, "write-failed", "cannot write: " + out_path, {}};
    }
    const std::size_t count = cia.Tmd().GetContentCount();
    std::vector<std::optional<Hash>> hashes(count);
    Cleanup cleanup;
    std::fstream out(out_path, std::ios::binary | std::ios::in | std::ios::out);
    for (std::size_t i = 0; i < count; ++i) {
        if (!cia.Present(i)) {
            continue;
        }
        const std::string temp = out_path + ".content" + std::to_string(i);
        cleanup.paths.push_back(temp);
        bool failed = false;
        {
            Service::AM::NCCHCryptoFile ncch(temp, false);
            ncch.AuthorizeDecryption();
            const bool read = cia.Stream(i, analysis.title_key, [&](const u8* data, std::size_t n) {
                ncch.Write(data, n);
            });
            failed = !read || ncch.IsError();
        }
        Hash hash{};
        u64 size = 0;
        if (failed || !Sha256File(temp, hash, size) || size != cia.Tmd().GetContentSizeByIndex(i)) {
            return Failure{ExitFailure, "decrypt-failed",
                           "content " + std::to_string(i) +
                               " could not be decrypted (wrong or incomplete keys?)",
                           {}};
        }
        hashes[i] = hash;
        std::ifstream in(temp, std::ios::binary);
        out.seekp(static_cast<std::streamoff>(cia.container.GetContentOffset(i)));
        std::vector<char> buffer(IoChunk);
        while (in) {
            in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            out.write(buffer.data(), in.gcount());
        }
    }
    std::vector<u8> tmd(cia.container.GetTitleMetadataSize());
    {
        FileUtil::IOFile file(cia.path, "rb");
        file.Seek(static_cast<s64>(cia.container.GetTitleMetadataOffset()), SEEK_SET);
        if (file.ReadBytes(tmd.data(), tmd.size()) != tmd.size()) {
            return Failure{ExitFailure, "read-failed", "cannot read the TMD", {}};
        }
    }
    if (!PatchTmd(tmd, hashes)) {
        return Failure{ExitFailure, "invalid-tmd", "unsupported TMD layout", {}};
    }
    out.seekp(static_cast<std::streamoff>(cia.container.GetTitleMetadataOffset()));
    out.write(reinterpret_cast<const char*>(tmd.data()), static_cast<std::streamsize>(tmd.size()));
    out.flush();
    if (!out) {
        return Failure{ExitFailure, "write-failed", "cannot write: " + out_path, {}};
    }
    return std::nullopt;
}

int Decrypt(const std::string& in_path, const std::string& out_path) {
    Cia cia(in_path);
    if (auto failure = cia.Open()) {
        return Report(*failure);
    }
    std::error_code ec;
    if (fs::exists(out_path, ec) && fs::equivalent(in_path, out_path, ec)) {
        return Report({ExitUsage, "same-file", "input and output must differ", {}});
    }
    const Analysis analysis = Analyze(cia);
    if (!analysis.missing.empty()) {
        return Report(MissingKeys(analysis.missing));
    }
    bool removed = false;
    if (auto failure = DecryptCia(cia, analysis, out_path, removed)) {
        fs::remove(out_path, ec);
        return Report(*failure);
    }
    std::cout << "{\"ok\":true," << ContentSummary(cia) << ",\"output\":\""
              << JsonEscape(out_path) << "\",\"content_layer_was_encrypted\":"
              << (analysis.content_layer_encrypted ? "true" : "false")
              << ",\"ncch_layer_was_encrypted\":"
              << (analysis.ncch_layer_encrypted ? "true" : "false") << "}\n";
    return ExitOk;
}

const char* InstallStatusName(Service::AM::InstallStatus status) {
    switch (status) {
    case Service::AM::InstallStatus::Success:
        return "success";
    case Service::AM::InstallStatus::ErrorFailedToOpenFile:
        return "open-failed";
    case Service::AM::InstallStatus::ErrorFileNotFound:
        return "not-found";
    case Service::AM::InstallStatus::ErrorAborted:
        return "aborted";
    case Service::AM::InstallStatus::ErrorInvalid:
        return "invalid-cia";
    case Service::AM::InstallStatus::ErrorEncrypted:
        return "encrypted";
    default:
        return "unknown";
    }
}

int Install(const std::string& in_path) {
    Cia cia(in_path);
    if (auto failure = cia.Open()) {
        return Report(*failure);
    }
    const Analysis analysis = Analyze(cia);
    if (!analysis.missing.empty()) {
        return Report(MissingKeys(analysis.missing));
    }
    // The emulator only installs plain titles: remove the crypto layers first when there are any.
    std::string source = in_path;
    Cleanup cleanup;
    if (analysis.content_layer_encrypted || analysis.ncch_layer_encrypted) {
        source = (fs::path(FileUtil::GetUserPath(FileUtil::UserPath::UserDir)) /
                  ("cia-install-" + TitleIdHex(cia.Tmd().GetTitleID()) + ".cia"))
                     .string();
        cleanup.paths.push_back(source);
        bool removed = false;
        if (auto failure = DecryptCia(cia, analysis, source, removed)) {
            return Report(*failure);
        }
    }
    const auto status = Service::AM::InstallCIA(source);
    if (status != Service::AM::InstallStatus::Success) {
        return Report({ExitFailure, std::string("install-") + InstallStatusName(status),
                       std::string("installation failed: ") + InstallStatusName(status), {}});
    }
    std::cout << "{\"ok\":true," << ContentSummary(cia) << ",\"installed\":true}\n";
    return ExitOk;
}

int Usage() {
    return Report({ExitUsage, "usage",
                   "usage: azahar-cia [--user-dir DIR] verify <in.cia> | decrypt <in.cia> "
                   "<out.cia> | install <in.cia>",
                   {}});
}

} // namespace

int main(int argc, char* argv[]) {
    std::vector<std::string> args(argv + 1, argv + argc);
    std::string user_dir;
    if (args.size() >= 2 && args[0] == "--user-dir") {
        user_dir = args[1];
        args.erase(args.begin(), args.begin() + 2);
    }
    if (args.empty()) {
        return Usage();
    }
    if (!user_dir.empty() && user_dir.back() != '/' && user_dir.back() != '\\') {
        user_dir += '/';
    }
    FileUtil::SetUserPath(user_dir);
    Common::Log::Initialize();
    Common::Log::Start();

    const std::string& command = args[0];
    if (command == "verify" && args.size() == 2) {
        return Verify(args[1]);
    }
    if (command == "decrypt" && args.size() == 3) {
        return Decrypt(args[1], args[2]);
    }
    if (command == "install" && args.size() == 2) {
        return Install(args[1]);
    }
    return Usage();
}
