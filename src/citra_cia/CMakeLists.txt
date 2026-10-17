add_executable(citra_cia
    citra_cia.cpp
)

set_target_properties(citra_cia PROPERTIES OUTPUT_NAME "azahar-cia")

if (BSD STREQUAL "NetBSD")
    include(DisablePaxMprotect)
    disable_pax_mprotect(citra_cia)
endif()

create_target_directory_groups(citra_cia)
target_link_libraries(citra_cia PRIVATE citra_common citra_core)

if(UNIX AND NOT APPLE)
    install(TARGETS citra_cia RUNTIME DESTINATION "${CMAKE_INSTALL_PREFIX}/bin")
endif()
