function(override_cache VAR VAL)
    get_property(VAR_STRINGS CACHE ${VAR} PROPERTY STRINGS)
    LIST(FIND VAR_STRINGS ${VAL} CK)
    if(-1 EQUAL ${CK} AND DEFINED VAR_STRINGS)
        message(SEND_ERROR
            "\"${VAL}\" is not valid override value for \"${VAR}\"."
            " Please select value from \"${VAR_STRINGS}\"\n")
    endif()
    set_property(CACHE ${VAR} PROPERTY VALUE ${VAL})
endfunction()

function(add_option NAME HELP_STRING DEFAULT VALUES)
    if(VALUES STREQUAL "yes;no")
        # Set the default value for the option.
        set(${NAME} ${DEFAULT} CACHE BOOL ${HELP_STRING})
    else()
        # Set the default value for the option.
        set(${NAME} ${DEFAULT} CACHE STRING ${HELP_STRING})
        # Set the list of allowed values for the option.
        set_property(CACHE ${NAME} PROPERTY STRINGS ${VALUES})
    endif()

    if(DEFINED ${NAME})
        list(FIND VALUES ${${NAME}} IDX)
        #
        # If the given value isn't in the list of allowed values for the option,
        # reduce it to yes/no according to CMake's "if" logic:
        # https://cmake.org/cmake/help/latest/command/if.html#basic-expressions
        #
        # This has no functional impact; it just makes the settings in
        # CMakeCache.txt and cmake-gui easier to read.
        #
        if (${IDX} EQUAL -1)
            if(${${NAME}})
                override_cache(${NAME} "yes")
            else()
                override_cache(${NAME} "no")
            endif()
        endif()
    endif()
endfunction()

function(wpkcs11_common_target_setup target_name runtime_dir dll_defs)
    target_include_directories(${target_name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
        ${ARGN})
    target_compile_definitions(${target_name} PRIVATE ${WOLFPKCS11_DEFINITIONS})
    if(BUILD_SHARED_LIBS)
        target_compile_definitions(${target_name} PRIVATE ${dll_defs})
    endif()
    target_link_libraries(${target_name} wolfssl::wolfssl)
    if(NOT BUILD_SHARED_LIBS)
        target_link_libraries(${target_name} wolfpkcs11::wolfpkcs11)
        target_compile_definitions(${target_name} PRIVATE "HAVE_PKCS11_STATIC")
    elseif(NOT WIN32)
        target_link_libraries(${target_name} ${CMAKE_DL_LIBS})
    endif()
    set_property(TARGET ${target_name}
                PROPERTY RUNTIME_OUTPUT_DIRECTORY
                ${runtime_dir})
endfunction()

function(add_wpkcs11_example target_name source_file)
    add_executable(${target_name} ${source_file})
    wpkcs11_common_target_setup(
        ${target_name}
        ${WOLFPKCS11_OUTPUT_BASE}/examples
        "${WOLFPKCS11_DLL_DEFINITION_FOR_EXAMPLES}"
        ${ARGN})
endfunction()

function(add_wpkcs11_test target_name source_file)
    add_executable(${target_name} ${source_file})
    wpkcs11_common_target_setup(
        ${target_name}
        ${WOLFPKCS11_OUTPUT_BASE}/tests
        "${WOLFPKCS11_DLL_DEFINITION_FOR_TESTS}"
        ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    add_test(NAME ${target_name}
                COMMAND $<TARGET_FILE:${target_name}>
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endfunction()
