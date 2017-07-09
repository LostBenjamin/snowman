set(SOURCES
    main.cpp
)

add_executable(debin_dump ${SOURCES})
target_link_libraries(debin_dump nc-core ${Boost_LIBRARIES})

if (NOT ${IDA_PLUGIN_ENABLED})
    install(TARGETS debin_dump RUNTIME DESTINATION bin)
    if(WIN32 AND NOT ${NC_QT5})
        install_qt4_executable("bin/debin_dump.exe")
    endif()
endif()

# vim:set et sts=4 sw=4 nospell:
