# SPDX-License-Identifier: LicenseRef-CSSL-1.0

# nr_srs_estimate_aoa() (nr_srs_aoa.h) is header-only and self-contained (no MAC/RRC/logging
# dependencies), so this test links only what the header itself needs - not the L2_NR library.
add_executable(test_nr_srs_aoa test_nr_srs_aoa.c)
target_include_directories(test_nr_srs_aoa PRIVATE
    ${OPENAIR_DIR}
    ${OPENAIR2_DIR}
)
target_link_libraries(test_nr_srs_aoa PRIVATE m)
add_dependencies(tests test_nr_srs_aoa)
add_test(NAME test_nr_srs_aoa COMMAND test_nr_srs_aoa)
