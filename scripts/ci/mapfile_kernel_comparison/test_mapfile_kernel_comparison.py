# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

import unittest
import logging
import pathlib
import re

from mapfile_kernel_comparison import MapfileKernelComparison


class TestMapfileKernelComparison(unittest.TestCase):

    def setUp(self):
        script_dir = pathlib.Path(__file__).resolve().parent
        self._test_data_dir = pathlib.Path(script_dir, 'test_data')

        self.maxDiff = None  # For debugging failures

        # logging.basicConfig(format='%(levelname)s; %(message)s',
        #                     level=logging.INFO,
        #                     datefmt='%Y-%m-%d %H:%M:%S')

    def test_missing_mapfile(self):
        perfmon_test_path = pathlib.Path(self._test_data_dir, '02_missing_mapfile', 'perfmon')
        kernel_test_path = pathlib.Path(self._test_data_dir, '02_missing_mapfile', 'linux')

        with self.assertRaises(FileNotFoundError) as assertion_context:
            mapfile_kernel_comparison = MapfileKernelComparison(perfmon_test_path, kernel_test_path)
        self.assertIn('mapfile.csv', str(assertion_context.exception))

    def test_missing_kernel_header(self):
        perfmon_test_path = pathlib.Path(self._test_data_dir, '03_missing_kernel_header', 'perfmon')
        kernel_test_path = pathlib.Path(self._test_data_dir, '03_missing_kernel_header', 'linux')

        with self.assertRaises(FileNotFoundError) as assertion_context:
            mapfile_kernel_comparison = MapfileKernelComparison(perfmon_test_path, kernel_test_path)
        self.assertIn('intel-family.h', str(assertion_context.exception))

    def test_mapfile_parsing(self):
        perfmon_test_path = pathlib.Path(self._test_data_dir, '00_snapshot_2022_08_29', 'perfmon')
        kernel_test_path = pathlib.Path(self._test_data_dir, '00_snapshot_2022_08_29', 'linux')

        mapfile_kernel_comparison = MapfileKernelComparison(perfmon_test_path, kernel_test_path)

        # Expect 127 rows
        self.assertEqual(127, mapfile_kernel_comparison._mapfile.shape[0])

        # Check model ID splitting
        mapfile_data = mapfile_kernel_comparison._mapfile.copy()
        calculated = mapfile_data[mapfile_data['Family-model'] == 'GenuineIntel-6-2E']
        self.assertEqual(['0x2E'], calculated['Model ID'].unique())

        mapfile_data = mapfile_kernel_comparison._mapfile.copy()
        calculated = mapfile_data[mapfile_data['Family-model'] == 'GenuineIntel-6-55-[56789ABCDEF]']
        self.assertEqual(['0x55'], calculated['Model ID'].unique())

    def test_kernel_header_parsing(self):
        perfmon_test_path = pathlib.Path(self._test_data_dir, '00_snapshot_2022_08_29', 'perfmon')
        kernel_test_path = pathlib.Path(self._test_data_dir, '00_snapshot_2022_08_29', 'linux')

        mapfile_kernel_comparison = MapfileKernelComparison(perfmon_test_path, kernel_test_path)

        self.assertEqual((68, 2), mapfile_kernel_comparison._intel_family_header.shape)

        # Check a few splits
        header_data = mapfile_kernel_comparison._intel_family_header.copy()
        header_data = header_data[header_data['Model'] == 'INTEL_FAM6_RAPTORLAKE']
        self.assertEqual(['0xB7'], header_data['Model ID'].to_list())

        # Verify #define INTEL_FAM6_ANY			X86_MODEL_ANY is not parsed
        header_data = mapfile_kernel_comparison._intel_family_header.copy()
        header_data = header_data[header_data['Model'] == 'INTEL_FAM6_ANY']
        self.assertEqual([], header_data['Model ID'].to_list())

    def test_comparison(self):
        perfmon_test_path = pathlib.Path(self._test_data_dir, '00_snapshot_2022_08_29', 'perfmon')
        kernel_test_path = pathlib.Path(self._test_data_dir, '00_snapshot_2022_08_29', 'linux')

        mapfile_kernel_comparison = MapfileKernelComparison(perfmon_test_path, kernel_test_path)

        self.assertEqual((19, 1), mapfile_kernel_comparison._missing[['Model']].shape)

        # Check a few expected missing
        lkf = mapfile_kernel_comparison._missing.copy()
        lkf = lkf[lkf['Model'] == 'INTEL_FAM6_LAKEFIELD']
        self.assertEqual(['warning'], lkf['Severity'].to_list())

    def test_rkl_added_to_mapfile(self):
        perfmon_test_path = pathlib.Path(self._test_data_dir, '01_rocketlake_added', 'perfmon')
        kernel_test_path = pathlib.Path(self._test_data_dir, '01_rocketlake_added', 'linux')

        mapfile_kernel_comparison = MapfileKernelComparison(perfmon_test_path, kernel_test_path)

        # Check RKL is not in the missing list
        rkl = mapfile_kernel_comparison._missing.copy()
        rkl = rkl[rkl['Model'] == 'INTEL_FAM6_ROCKETLAKE']
        self.assertTrue(rkl.empty)

    def test_simple_missing_tgl(self):
        perfmon_test_path = pathlib.Path(self._test_data_dir, '04_simple_tgl_missing', 'perfmon')
        kernel_test_path = pathlib.Path(self._test_data_dir, '04_simple_tgl_missing', 'linux')

        mapfile_kernel_comparison = MapfileKernelComparison(perfmon_test_path, kernel_test_path)
        missing = mapfile_kernel_comparison._missing.copy()

        # Expect only one missing ID
        self.assertEqual(1, missing.shape[0])

        expected_row = ['INTEL_FAM6_TIGERLAKE', '0x8D', 'error', '']
        self.assertEqual(expected_row, missing.iloc[0].to_list())

        self.assertTrue(mapfile_kernel_comparison.mapfile_is_missing_model())

    def test_none_missing(self):
        perfmon_test_path = pathlib.Path(self._test_data_dir, '05_none_missing', 'perfmon')
        kernel_test_path = pathlib.Path(self._test_data_dir, '05_none_missing', 'linux')

        mapfile_kernel_comparison = MapfileKernelComparison(perfmon_test_path, kernel_test_path)
        missing = mapfile_kernel_comparison._missing.copy()

        # Expect 0 'error' rows
        self.assertEqual(0, missing[missing['Severity'] == 'error'].shape[0])
        self.assertFalse(mapfile_kernel_comparison.mapfile_is_missing_model())

    def test_print_error(self):
        perfmon_test_path = pathlib.Path(self._test_data_dir, '04_simple_tgl_missing', 'perfmon')
        kernel_test_path = pathlib.Path(self._test_data_dir, '04_simple_tgl_missing', 'linux')

        mapfile_kernel_comparison = MapfileKernelComparison(perfmon_test_path, kernel_test_path)

        with self.assertLogs() as cm:
            mapfile_kernel_comparison.print_results()

            # Expect an error message about TGL
            error_re = re.compile(r'ERROR.*INTEL_FAM6_TIGERLAKE.*')
            matches = list(filter(error_re.match, cm.output))
            self.assertTrue(matches)

            # There should not be a message about known mismatches
            warnings_re = re.compile(r'.*known acceptable mismatches.*')
            matches = list(filter(warnings_re.match, cm.output))
            self.assertFalse(matches)

    def test_no_known_missing(self):
        perfmon_test_path = pathlib.Path(self._test_data_dir, '06_kernel_removed_known_missing',
                                         'perfmon')
        kernel_test_path = pathlib.Path(self._test_data_dir, '06_kernel_removed_known_missing',
                                        'linux')

        mapfile_kernel_comparison = MapfileKernelComparison(perfmon_test_path, kernel_test_path)
        missing = mapfile_kernel_comparison._missing.copy()

        # Expect 0 'warning' rows
        self.assertEqual(0, missing[missing['Severity'] == 'warning'].shape[0])
        # Also expect 0 'error' rows
        self.assertEqual(0, missing[missing['Severity'] == 'error'].shape[0])
        self.assertFalse(mapfile_kernel_comparison.mapfile_is_missing_model())
