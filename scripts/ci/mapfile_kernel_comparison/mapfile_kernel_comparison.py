#!/usr/bin/env python3
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import logging
import pandas as pd
import re
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


class MapfileKernelComparison():

    def __init__(self, perfmon_repo_path, kernel_repo_path):
        self._perfmon_repo_path = Path(perfmon_repo_path)
        self._kernel_repo_path = Path(kernel_repo_path)

        # Setup input file paths
        self._mapfile_path = Path(self._perfmon_repo_path, 'mapfile.csv')
        self._intel_family_header_path = Path(self._kernel_repo_path, 'arch', 'x86', 'include',
                                              'asm', 'intel-family.h')

        self._mapfile = ''  # Data from mapfile.csv
        self._intel_family_header = ''  # Data from intel-family.h
        self._missing = ''  # IDs in the kernel, but missing from mapfile.csv

        # Build a set of intentionally missing IDs. These are IDs we are not going
        # to publish in mapfile.csv.
        self._known_missing = pd.DataFrame(
            [('0x09', 'Quark event files are not published.'),
             ('0x0E', 'Yonah event files are not published.'),
             ('0x0F', 'Core2 event files are not published.'),
             ('0x16', 'Core2 event files are not published.'),
             ('0x17', 'Core2 event files are not published.'),
             ('0x1D', 'Core2 event files are not published.'),
             ('0x66', 'Cannonlake event files are not published.'),
             ('0x75', 'Lightning Mountain event files are not published.'),
             ('0x8A', 'Lakefield event files are not published.'),
             ('0x9D', 'Spring Hill event files are not published.')],
            columns=['Model ID', 'Description'])

        self._start()

    def _start(self):
        """Helper method to run individual steps"""
        self._load_mapfile_data()
        self._load_kernel_family_header_data()
        self._compare()

    def _load_mapfile_data(self):
        """Read mapfile.csv and process columns as necessary"""
        if not self._mapfile_path.exists():
            raise FileNotFoundError('Missing {}'.format(self._mapfile_path))

        logger.info('Loading {}.'.format(self._mapfile_path))
        self._mapfile = pd.read_csv(self._mapfile_path)
        self._mapfile = self._mapfile.fillna('')

        # Create a Model ID column
        #   GenuineIntel-6-2E -> 0x2E
        #   GenuineIntel-6-55-[01234] -> 0x55
        #   GenuineIntel-6-A7 -> 0xA7
        model_id_re = re.compile(r'^(\w*)-(\d)-([\da-zA-Z]{2})(.*)')
        # Only keep the third group containing model ID
        model_id_sub = r'0x\g<3>'

        self._mapfile['Model ID'] = self._mapfile['Family-model'].apply(
            lambda x: model_id_re.sub(model_id_sub, x))

    def _load_kernel_family_header_data(self):
        """Read intel-family.h and process columns as necessary"""
        # Match specific #define lines.
        #  #define INTEL_FAM6_ATOM_AIRMONT		0x4C /* Cherry Trail, Braswell */
        #    -> ('INTEL_FAM6_ATOM_AIRMONT', '0x4C')
        model_re = re.compile(r'^#define\W*(\w*)\W*(0x[\da-zA-Z]{2})')

        if not self._intel_family_header_path.exists():
            raise FileNotFoundError('Missing {}'.format(self._intel_family_header_path))

        logger.info('Loading {}.'.format(self._intel_family_header_path))
        matches = []
        with open(self._intel_family_header_path, 'r') as family_header:
            for line in family_header.readlines():
                match = model_re.match(line)
                if match:
                    model = match[1]
                    model_id = match[2]
                    matches.append((model, model_id))

        self._intel_family_header = pd.DataFrame(matches, columns=['Model', 'Model ID'])

    def _compare(self):
        """Compare each kernel ID to the perfmon mapfile.csv"""
        logger.info('Finding {} model IDs missing in {}.'.format(
            self._intel_family_header_path.name, self._mapfile_path.name))
        df = self._intel_family_header.copy()
        # Build a column with True/False comparing model IDs between the two dataframes
        df['In Mapfile'] = self._intel_family_header['Model ID'].isin(self._mapfile['Model ID'])
        # Keep rows that are not present in mapfile.csv
        df = df[df['In Mapfile'] == False]

        self._missing = df[['Model', 'Model ID']].copy()
        self._missing = self._missing.sort_values('Model ID')
        self._missing['Severity'] = 'error'  # Default severity
        self._missing['Description'] = ''

        # Update any known missing
        logger.info('Setting known or intentionally missing IDs.')
        for model_id, description in self._known_missing.itertuples(index=False):
            self._missing.loc[self._missing['Model ID'] == model_id, 'Severity'] = 'warning'
            self._missing.loc[self._missing['Model ID'] == model_id, 'Description'] = description

    def print_results(self):
        missing_warnings = self._missing[self._missing['Severity'] == 'warning'].copy()
        missing_errors = self._missing[self._missing['Severity'] == 'error'].copy()
        if missing_warnings.empty and missing_errors.empty:
            logger.info('Mapfile and kernel model IDs are in sync.')
            return

        if not missing_warnings.empty:
            logger.warning('Mapfile and kernel have the following known acceptable mismatches.')
            for model, model_id, _, description in missing_warnings.itertuples(index=False):
                logger.warning('  {:<32} {}  {}'.format(model, model_id, description))

        if not missing_errors.empty:
            logger.error('Mapfile and kernel are out of sync!')
            for model, model_id, _, _ in missing_errors.itertuples(index=False):
                logger.error('  {:<32} {}'.format(model, model_id))

    def mapfile_is_missing_model(self):
        """Return true if there are missing models"""
        missing_errors = self._missing[self._missing['Severity'] == 'error'].copy()

        if missing_errors.empty:
            return False

        return True


if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s;%(levelname).4s; %(message)s',
                        level=logging.INFO,
                        datefmt='%Y-%m-%d')

    script_dir = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(description='Compare perfmon mapfile.csv to the Linux kernel.')
    parser.add_argument('-k',
                        '--kernel_repo_path',
                        required=True,
                        type=Path,
                        help='Path to local Linux kernel checkout.')
    args = parser.parse_args()

    perfmon_repo_path = script_dir.parents[2]
    kernel_repo_path = args.kernel_repo_path.resolve()

    mapfile_kernel_comparison = MapfileKernelComparison(perfmon_repo_path, kernel_repo_path)
    mapfile_kernel_comparison.print_results()

    # Exit with a non-zero value if necessary.
    if mapfile_kernel_comparison.mapfile_is_missing_model():
        logger.error('Comparison failed. Updates are required.')
        sys.exit(1)
    else:
        logger.info('Mapfile and kernel are in sync.')
