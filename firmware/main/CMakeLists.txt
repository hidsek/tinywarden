idf_component_register(
    SRCS "main.c" "util.c" "clock.c" "store.c" "logstore.c" "button.c" "led.c" "usb_net.c" "usb_ecm_glue.c" "tls.c" "auth.c" "api.c" "web.c"
    INCLUDE_DIRS "."
    REQUIRES esp_app_format hal esp_rom esp_https_server esp_netif esp_timer nvs_flash
             esp_partition driver mbedtls json
    # Scripts for the pages, served under /web/ (web.c). Symbols use the file name only, so names must be unique.
    EMBED_FILES "../web/status.js" "../web/unlock.js" "../web/twcrypto.js" "../web/merge.html" "../web/merge-ui.js" "../web/merge.js"
                "../web/vendor/noble-hashes/argon2.js" "../web/vendor/noble-hashes/_u64.js"
                "../web/vendor/noble-hashes/blake2.js" "../web/vendor/noble-hashes/_blake.js"
                "../web/vendor/noble-hashes/_md.js" "../web/vendor/noble-hashes/utils.js"
                "../web/vendor/noble-hashes/LICENSE"
)

# The device has no clock, so the build time is the floor for its time (SPEC 4)
string(TIMESTAMP TW_BUILD_EPOCH "%s" UTC)
target_compile_definitions(${COMPONENT_LIB} PRIVATE TW_BUILD_EPOCH=${TW_BUILD_EPOCH})

# The manual page (GET /manual, only with the status page unlocked): docs/*.md turned into one gzipped HTML
# page at build time, so the board serves the manual of the firmware it runs (tools/md2html.py)
idf_build_get_property(python PYTHON)
set(TW_DOCS_DIR ${CMAKE_CURRENT_LIST_DIR}/../../docs)
set(TW_MANUAL_DOCS ${TW_DOCS_DIR}/MANUAL.md ${TW_DOCS_DIR}/SETUP.md ${TW_DOCS_DIR}/MANUAL.en.md ${TW_DOCS_DIR}/SETUP.en.md)
set(TW_MANUAL ${CMAKE_CURRENT_BINARY_DIR}/manual.html.gz)
add_custom_command(OUTPUT ${TW_MANUAL}
    COMMAND ${python} ${CMAKE_CURRENT_LIST_DIR}/../../tools/md2html.py ${TW_MANUAL} ${TW_MANUAL_DOCS}
    DEPENDS ${CMAKE_CURRENT_LIST_DIR}/../../tools/md2html.py ${TW_MANUAL_DOCS}
    VERBATIM)
add_custom_target(tw_manual DEPENDS ${TW_MANUAL})
add_dependencies(${COMPONENT_LIB} tw_manual)
target_add_binary_data(${COMPONENT_LIB} ${TW_MANUAL} BINARY DEPENDS tw_manual)
