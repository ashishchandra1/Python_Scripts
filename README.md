Python_Scripts
==============

#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2013 NTT DATA CORPORATION
# 著作者の許可なく変更・配布を禁止します。

"""
This script reports free and available memory details to ganglia.

 Changelog:
   v1.0 - 2013-30-07
"""

import logging
from logging import handlers as loghandler
import os
import subprocess
import sys

VALID_MEMORY_UNITS = ['BYTES', 'KB', 'MB', 'GB']
VALID_LOG_LEVELS = ['DEBUG', 'INFO', 'ERROR', 'WARNING']
METRIC_MAP = {}
LOG = logging.getLogger('mem_usage')

MEMINFO_DICT = {
    'free memory': 0.0,
    'used memory': 0.0,
    'buffer memory': 0.0,
    'swap cache': 0.0,
    'used swap': 0.0,
    'inactive memory': 0.0
}


def _setup_logging(lparams):
    """
        Set logging options.

        :lparams - configuration parameters
    """

    global LOG
    log_handler = None
    use_syslog = lparams.get('use_syslog')
    if use_syslog and use_syslog.lower() in ["true", "yes", "1"]:
        logging_facility = lparams.get('logging_facility')
        if logging_facility in loghandler.SysLogHandler.facility_names:
            log_handler = loghandler.SysLogHandler(address='/dev/log',
                                                   facility=logging_facility)
        else:
            print "Invalid logging_facility (%s) parameter" \
                % logging_facility
            log_handler = loghandler.SysLogHandler(address='/dev/log')
    else:
        log_handler = logging.StreamHandler()

    if 'logging_format' not in lparams:
        log_format = logging.Formatter('%(levelname)s '
                                       '[%(name)s] %(message)s')
    else:
        log_format = logging.Formatter(lparams['logging_format'])

    log_handler.setFormatter(log_format)
    LOG.addHandler(log_handler)

    logging_level = lparams.get('logging_level')
    if logging_level is None or logging_level not in VALID_LOG_LEVELS:
        log_msg = "Invalid logging_level (%s) parameter" \
            % logging_level
        LOG.warning(log_msg)
        LOG.setLevel(logging.getLevelName('DEBUG'))
    else:
        LOG.setLevel(logging.getLevelName(logging_level))


def convert_memory_size(memory, memory_unit):
    """
        Convert memory on the basis of unit

        :memory - Memory in kb
        :memory_unit - Unit of memory (bytes/kb/mb/gb)
    """

    if memory_unit == "BYTES":
        memory_size = memory * 1024
    elif memory_unit == "KB":
        memory_size = memory
    elif memory_unit == "MB":
        memory_size = memory / 1024
    elif memory_unit == "GB":
        memory_size = memory / (1024 * 1024)
    else:
        log_msg = "Invalid memory_unit (%s) specified" % memory_unit
        LOG.error(log_msg)
        memory_size = 0

    return memory_size


def get_memory_info(name):
    """
        Return a memory information for the requested metric

        :name - name of the metric
    """

    global MEMINFO_DICT

    try:
        process = subprocess.Popen(["vmstat", "-sn"], stdout=subprocess.PIPE)
        output, err = process.communicate()
    except OSError as ex:
        LOG.error(ex)
        return 0

    memory_unit = METRIC_MAP[name]['units']
    meminfo_keys = MEMINFO_DICT.keys()

    for line in output.split("\n"):
        if line:
            mem_data = line.strip().split(' ', 1)
            if mem_data[0]:
                memory_type = mem_data[1].strip()
                for key in meminfo_keys:
                    if memory_type.find(key) >= 0:
                        meminfo_keys.remove(key)
                        MEMINFO_DICT[key] = long(mem_data[0])
                        break

    if meminfo_keys:
        log_msg = "[%s] value(s) not in 'vmstat -sn' output" \
            % ', '.join(meminfo_keys)
        LOG.error(log_msg)
        return 0

    if name == 'memory_free':
        # calculate free memory
        free_memory = MEMINFO_DICT['free memory'] + \
            MEMINFO_DICT['inactive memory']
        memory_size = convert_memory_size(float(free_memory), memory_unit)
    elif name == 'memory_used':
        # calculate used memory
        used_memory = MEMINFO_DICT['used memory'] - \
            MEMINFO_DICT['buffer memory'] - \
            MEMINFO_DICT['swap cache'] + MEMINFO_DICT['used swap']

        memory_size = convert_memory_size(float(used_memory), memory_unit)
    else:
        log_msg = "Invalid metric name (%s) specified" \
            % name
        LOG.error(log_msg)
        memory_size = 0

    return memory_size


def create_desc(skel, prop):
    """
        Create descriptor based on skel.

        :skel is skeleton to prepare gmond descriptor
        :prop is metric properties
    """
    desc = skel.copy()
    for key, value in prop.iteritems():
        desc[key] = value
    return desc


def _prepare_mem_usage_descriptors(desc_skel, unit):
    """
        Prepares descriptor for memory usage related metrics.

        :desc_skel is skeleton dict to create descriptor.
        :unit - Unit of memory (bytes/kb/mb/gb)
    """

    global METRIC_MAP

    descriptors = []
    descriptors.append(create_desc(desc_skel, {
        "name": "memory_free",
                "orig_name": "FreeMemory",
                "description": "Amount of memory free in (%s)" % unit,
    }))
    METRIC_MAP["memory_free"] = {"units": desc_skel['units']}

    descriptors.append(create_desc(desc_skel, {
        "name": "memory_used",
                "orig_name": "UsedMemory",
                "description": "Amount of memory used in (%s)" % unit,
    }))
    METRIC_MAP["memory_used"] = {"units": desc_skel['units']}

    return descriptors


def metric_init(params):
    """
        Initialize ganglia plugin.
    """

    _setup_logging(params)

    unit = params.get('mem_unit')
    if unit is None or unit.upper() not in VALID_MEMORY_UNITS:
        log_msg = "Invalid mem_unit (%s) parameter value" \
            % unit
        LOG.error(log_msg)
        return []

    desc_skel = {
        'name': 'no name',
        'call_back': get_memory_info,
        'time_max': 60,
        'value_type': 'float',
        'format': '%0.2f',
        'units': unit.upper(),
        'slope': 'both',
        'description': 'no description',
        'groups': 'memory_usage'
    }

    LOG.info("Plugin started")

    return _prepare_mem_usage_descriptors(desc_skel, unit.upper())


def metric_cleanup():
    """
        Clean up metric module.
    """

    LOG.info("Terminating plugin")

if __name__ == '__main__':
    try:
        params = {
            'mem_unit': 'MB',
            'logging_level': 'DEBUG',
            'logging_format': '%(levelname)s [%(name)s] %(message)s',
            'use_syslog': "yes",
            'logging_facility': 'local1'
        }

        descriptors = metric_init(params)
        for d in descriptors:
            print (('%s = %s %s')
                   % (d['name'], d['format'] % (d['call_back'](d['name'])),
                      d['units']))

    except Exception, ex:
        LOG.error(ex)
        sys.exit(0)



































#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2013 NTT DATA CORPORATION
# 著作者の許可なく変更・配布を禁止します。
#

"""
This ganglia plugin reports input/output statistics of devices to ganglia.

 Change log:
   v1.0 - 2013-13-09
"""

import logging
from logging import handlers as loghandler
import os
import subprocess
import sys
import time
import traceback

VALID_MEMORY_UNITS = ['BLOCKS', 'BYTES', 'KB', 'MB']
VALID_LOG_LEVELS = ['DEBUG', 'INFO', 'ERROR', 'WARNING']
METRIC_MAP = {}
NAME_PREFIX = "iostat_"

LOG = logging.getLogger('iostatx')

IOSTAT_METRICS = {
    'rrqm': {
    'command_output_name': 'rrqm/s',
    'unit': 'Queued Requests/s',
    'conversion': {},
    'description': 'The number of read requests merged per second \
that were queued to the device'
    },
'wrqm': {
    'command_output_name': 'wrqm/s',
    'unit': 'Queued Requests/s',
    'conversion': {},
    'description': 'The number of write requests merged per second \
that were queued to the device'
},
'read-req': {
    'command_output_name': 'r/s',
    'unit': 'Requests/s',
    'conversion': {},
    'description': 'The number of read requests that were issued \
to the device per second'
},
'write-req': {
    'command_output_name': 'w/s',
    'unit': 'Requests/s',
    'conversion': {},
    'description': 'The number of write requests that were issued \
to the device per second'
},
'read': {
    'command_output_name': 'rsec/s',
    'unit': 'Sectors/s',
    'parameter': {'KB': '-k', 'MB': '-m'},
    'conversion': {
    'method': {'BYTES': lambda x: x * 512},
    'output_name': {'KB': 'rkB/s', 'MB': 'rMB/s'}
    },
    'description': 'The number of sectors read from the device per second'
},
'write': {
    'command_output_name': 'wsec/s',
    'unit': 'Sectors/s',
    'parameter': {'KB': '-k', 'MB': '-m'},
    'conversion': {
    'method': {'BYTES': lambda x: x * 512},
    'output_name': {'KB': 'wkB/s', 'MB': 'wMB/s'}
    },
    'description': 'The number of sectors written to the device per second'
},
'avgrq-sz': {
    'command_output_name': 'avgrq-sz',
    'unit': 'Sectors',
    'conversion': {},
    'description': 'The average size (in sectors) of the requests \
that were issued to the device'
},
'avgqu-sz': {
    'command_output_name': 'avgqu-sz',
    'unit': 'Sectors',
    'conversion': {},
    'description': 'The average queue length of the requests that \
were issued to the device'
},
'await': {
    'command_output_name': 'await',
    'unit': 'milliseconds',
    'conversion': {},
    'description': 'The average time (in ms) for I/O requests issued \
to the device to be served'
},
'svctm': {
    'command_output_name': 'svctm',
    'unit': 'milliseconds',
    'conversion': {},
    'description': 'The average service time (in ms) for I/O requests \
that were issued to the device'
},
'util': {
    'command_output_name': '%util',
    'unit': '%',
    'conversion': {},
    'description': 'Percentage of CPU time during which I/O requests \
were issued to the device'
}
}


def _setup_logging(lparams):
    """
        Set logging options.

        :lparams - configuration parameters
    """

    global LOG
    log_handler = None
    use_syslog = lparams.get('use_syslog')
    if use_syslog and use_syslog.lower() in ["true", "yes", "1"]:
        logging_facility = lparams.get('logging_facility')
        if logging_facility in loghandler.SysLogHandler.facility_names:
            log_handler = loghandler.SysLogHandler(address='/dev/log',
                                                   facility=logging_facility)
        else:
            print "Invalid logging_facility (%s) parameter" \
                % logging_facility
            log_handler = loghandler.SysLogHandler(address='/dev/log')
    else:
        log_handler = logging.StreamHandler()

    if 'logging_format' not in lparams:
        log_format = logging.Formatter('%(levelname)s '
                                       '[%(name)s] %(message)s')
    else:
        log_format = logging.Formatter(lparams['logging_format'])

    log_handler.setFormatter(log_format)
    LOG.addHandler(log_handler)

    logging_level = lparams.get('logging_level')
    if logging_level is None or logging_level not in VALID_LOG_LEVELS:
        log_msg = "Invalid logging_level (%s) parameter" \
            % logging_level
        LOG.warning(log_msg)
        LOG.setLevel(logging.getLevelName('DEBUG'))
    else:
        LOG.setLevel(logging.getLevelName(logging_level))


def get_iostatx(name):
    """
        Return a iostat information for the requested metric
        :name - name of the metric
    """

    device = METRIC_MAP[name]['device']
    unit = METRIC_MAP[name]['unit']
    metric = METRIC_MAP[name]['metric']

    command = 'iostat -dx %s' % device
    parameter = IOSTAT_METRICS[metric].get('parameter')

    if parameter:
        parameter_unit = parameter.get(unit)
        if parameter_unit:
            command += (' ' + parameter_unit)

    try:
        process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
        output, err = process.communicate()
        if err:
            LOG.error(err)
            return 0
    except OSError as ex:
        LOG.error("Failed to run iostat command for device[%s], error:%s" %
                  (device, ex))
        return 0

    stats = []
    for line in output.split("\n"):
        if not line:
            continue
        stats.append(line.split())

    if not len(stats) > 1:
        LOG.error('iostat command failed to return correct input/output '
                  'statistics for device[%s]' % device)
        return 0

    stats = stats[1:]

    if len(stats) == 2 and (len(stats[0]) == len(stats[1])):
        iostats_output = dict(zip(stats[0], stats[1]))
    else:
        msg = 'iostat command failed to return input/output statistics ' \
              'for device[%s]' % device
        LOG.error(msg)
        return 0

    command_output_name = IOSTAT_METRICS[metric]['command_output_name']
    conversion = IOSTAT_METRICS[metric]['conversion']

    if conversion:
        output_name = conversion.get('output_name').get(unit)
        if output_name:
            command_output_name = output_name

    value = iostats_output.get(command_output_name)
    if not value:
        msg = 'Failed to read value for statistics[%s] for device[%s]' % \
              (command_output_name, device)
        LOG.error(msg)
        return 0

    if conversion:
        method = conversion.get('method')
        if method:
            func = method.get(unit)
            if func:
                value = func(float(value))

    return float(value)


def metric_init(params):
    """
        Initialize ganglia plugin.
        :params - configuration parameters
    """

    global METRIC_MAP
    _setup_logging(params)

    unit = params.get('iostat_unit')

    if unit is None or unit.upper() not in VALID_MEMORY_UNITS:
        log_msg = "Invalid iostat_unit (%s) parameter value" \
            % unit
        LOG.error(log_msg)
        return []

    unit = unit.upper()

    target_devices = params.get('target_devices')
    if not target_devices:
        LOG.error('Parameter target_devices should not be empty')
        return []

    target_devices = target_devices.split(',')
    unique_devices = list(set(target_devices))
    if len(target_devices) != len(unique_devices):
        LOG.warn('Parameter target_devices contains some duplicate devices. '
                 'These duplicate devices will be ignored')

    descriptors = []

    for device_name in target_devices:
        device_name = device_name.strip()
        if not device_name:
            LOG.error('Device name should not be empty and it should not '
                      'contain any whitespaces')
            continue

        for metric in IOSTAT_METRICS:
            metric_name = "%s%s_%s" % (NAME_PREFIX, device_name, metric)
            descriptors.append({
                'name': metric_name,
                'call_back': get_iostatx,
                'value_type': 'float',
                'units': IOSTAT_METRICS[metric]['unit'],
                'slope': 'both',
                'format': '%0.2f',
                'description': IOSTAT_METRICS[metric]['description'],
                'groups': 'iostats'
            })

            METRIC_MAP[metric_name] = {
                "unit": unit, 'device': device_name, 'metric': metric}

    LOG.info("Plugin started")
    return descriptors


def metric_cleanup():
    """
        Clean up metric module.
    """

    LOG.info("Terminating plugin")

if __name__ == '__main__':
    try:
        params = {
            'iostat_unit': 'blocks',
            'target_devices': 'sda',
            'logging_level': 'DEBUG',
            'logging_format': '%(levelname)s [%(name)s] %(message)s',
            'use_syslog': "no",
            'logging_facility': 'local1'
        }

        descriptors = metric_init(params)
        while(True):
            try:
                for d in descriptors:
                    print(("%s = %s %s") % (
                        d['name'], (d['call_back'](d['name'])), d['units']))
                time.sleep(1)
            except Exception as ex:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                traceback.print_tb(exc_traceback)

    except Exception, ex:
        print ex




































#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2013 NTT DATA CORPORATION
# 著作者の許可なく変更・配布を禁止します。
#
# Disk Usage gmond module for Ganglia
#

import logging
from logging import handlers as loghandler
import os
import re

MIN_DISK_SIZE = 0
NAME_PREFIX = 'disk_usage_'
DISK_SIZE_PREFIX = 'disk_size_absolute_'
PATHS = {}
METRIC_MAP = {}

VALID_DISK_UNITS = ['BYTES', 'KB', 'MB', 'GB', 'TB']
VALID_LOG_LEVELS = ['DEBUG', 'INFO', 'ERROR', 'WARNING']

LOG = logging.getLogger('diskusage')


def calculate_disk_size(unit_type, disk_space):
    """
        Calculate the disk size on the basis of unit_type

        :unit_type - Type of unit (bytes/kb/mb/gb/tb)
        :disk_space - Disk space in bytes
    """

    if unit_type == "BYTES":
        result = disk_space
    elif unit_type == "KB":
        result = float(disk_space / 1024)
    elif unit_type == "MB":
        result = float(disk_space / 1024 ** 2)
    elif unit_type == "GB":
        result = float(disk_space / 1024 ** 3)
    elif unit_type == "TB":
        result = float(disk_space / 1024 ** 4)
    else:
        log_msg = "Invalid unit_type (%s) specified" % unit_type
        LOG.error(log_msg)
        result = 0

    return result


def get_disk_usage(name):
    """
        Return a disk usage for the requested metric

        :name - name of the metric
    """

    # parse unit type and path from name
    result = 0
    if name.startswith(DISK_SIZE_PREFIX):
        unit_type = 'size'
        name_parser = re.match("^%s(.*)$" % DISK_SIZE_PREFIX, name)
        if name_parser.group(1) == 'rootfs':
            path = '/'
        elif name_parser.group(1) in PATHS:
            path = '/' + PATHS[name_parser.group(1)]
        else:
            path = '/' + name_parser.group(1).replace('_', '/')
    else:
        name_parser = re.match(
            "^%s(absolute|percent)_(.*)$" % NAME_PREFIX, name)
        unit_type = name_parser.group(1)
        if name_parser.group(2) == 'rootfs':
            path = '/'
        elif name_parser.group(2) in PATHS:
            path = '/' + PATHS[name_parser.group(2)]
        else:
            path = '/' + name_parser.group(2).replace('_', '/')

    # get fs stats
    try:
        disk = os.statvfs(path)
        unit = METRIC_MAP[name]['units']

        # Total used disk space in bytes
        total_used_space = float(disk.f_bsize * (disk.f_blocks - disk.f_bfree))
        total_space = float(disk.f_blocks * disk.f_frsize)
        if total_space > 0:
            if unit_type == 'percent':
                result = (float(total_used_space) / total_space) * 100
            elif unit_type == 'size':
                result = calculate_disk_size(unit, total_space)
            else:
                # unit_type = 'absolute'
                result = calculate_disk_size(unit, total_used_space)

    except OSError as error:
        result = 0
        LOG.error(error)

    return result


def _setup_logging(lparams):
    """
        Set logging options.

        :lparams - configuration parameters
    """

    global LOG
    log_handler = None
    use_syslog = lparams.get('use_syslog')
    if use_syslog and use_syslog.lower() in ["true", "yes", "1"]:
        logging_facility = lparams.get('logging_facility')
        if logging_facility in loghandler.SysLogHandler.facility_names:
            log_handler = loghandler.SysLogHandler(address='/dev/log',
                                                   facility=logging_facility)
        else:
            print "Invalid logging_facility (%s) parameter" \
                % logging_facility
            log_handler = loghandler.SysLogHandler(address='/dev/log')
    else:
        log_handler = logging.StreamHandler()

    if 'logging_format' not in lparams:
        log_format = logging.Formatter('%(levelname)s '
                                       '[%(name)s] %(message)s')
    else:
        log_format = logging.Formatter(lparams['logging_format'])

    log_handler.setFormatter(log_format)
    LOG.addHandler(log_handler)

    logging_level = lparams.get('logging_level')
    if logging_level is None or logging_level not in VALID_LOG_LEVELS:
        log_msg = "Invalid logging_level (%s) parameter" \
            % logging_level
        LOG.warning(log_msg)
        LOG.setLevel(logging.getLevelName('DEBUG'))
    else:
        LOG.setLevel(logging.getLevelName(logging_level))


def metric_init(lparams):
    """
        Initialize metric descriptors

        :lparams - configuration parameters
    """

    global METRIC_MAP

    # set logging options
    _setup_logging(lparams)

    # get disk units from diskusage.pyconf
    disk_size_unit = lparams.get('disk_size_unit')
    if disk_size_unit:
        disk_size_unit = disk_size_unit.upper()
        if disk_size_unit not in VALID_DISK_UNITS:
            log_msg = "Invalid unit (%s) for parameter (disk_size_unit)" \
                      % (disk_size_unit)
            LOG.error(log_msg)
            return []
    else:
        log_msg = "'disk_size_unit' parameter is not configured"
        LOG.error(log_msg)
        return []

    disk_usage_unit = lparams.get('disk_usage_unit')
    if disk_usage_unit:
        disk_usage_unit = disk_usage_unit.upper()
        if disk_usage_unit not in VALID_DISK_UNITS:
            log_msg = "Invalid unit (%s) for parameter (disk_usage_unit)" \
                      % (disk_usage_unit)
            LOG.error(log_msg)
            return []
    else:
        log_msg = "'disk_usage_unit' parameter is not configured"
        LOG.error(log_msg)
        return []

    # read mounts file
    try:
        if 'mount_file' in lparams:
            with open(lparams['mount_file'], 'r') as infile:
                lines = infile.readlines()
        else:
            log_msg = "mount_file param is not defined in diskusage.pyconf"
            LOG.error(log_msg)
            lines = []
    except IOError as error:
        LOG.error(error)
        lines = []

    # parse mounts and create descriptors
    descriptors = []

    for line in lines:
        # We only want local file systems
        if line.startswith('/') or line.startswith('tmpfs'):
            mount_info = line.split()

            # create key from path
            if mount_info[1] == '/':
                path_key = 'rootfs'
            else:
                path_key = mount_info[1][1:].replace('/', '_')

            # Calculate the size of the disk. We'll use it exclude small disks
            disk = os.statvfs(mount_info[1])
            disk_size = (disk.f_blocks * disk.f_frsize) / float(2 ** 30)

            if disk_size >= MIN_DISK_SIZE and mount_info[1] != "/dev":
                PATHS[path_key] = mount_info[1]
                for unit_type in ['absolute', 'percent', 'size']:
                    metric_name = NAME_PREFIX + unit_type + '_' + path_key

                    if unit_type == 'percent':
                        units = '%'
                        description = "Disk space used (%s) on %s" \
                            % (units, mount_info[1])
                    elif unit_type == 'absolute':
                        units = disk_usage_unit
                        description = "Disk space used (%s) on %s" \
                            % (units, mount_info[1])
                    else:
                        units = disk_size_unit
                        metric_name = DISK_SIZE_PREFIX + path_key
                        description = "Total disk space in (%s) on %s" \
                            % (units, mount_info[1])

                    descriptors.append({
                        'name': metric_name,
                        'call_back': get_disk_usage,
                        'time_max': 60,
                        'value_type': 'float',
                        'units': units,
                        'slope': 'both',
                        'format': '%0.2f',
                        'description': description,
                        'groups': 'disk_usage'
                    })
                    METRIC_MAP[metric_name] = {"units": units}

    LOG.info("Plugin started ")

    return descriptors


def metric_cleanup():
    """
        Cleanup
    """

    LOG.info("Terminating plugin")


# the following code is for debugging and testing
if __name__ == '__main__':
    params = {
        'mount_file': '/proc/mounts',
        'disk_size_unit': 'mb',
        'disk_usage_unit': 'mb',
        'logging_facility': 'local1',
        'logging_format': '%(levelname)s [%(name)s] %(message)s',
        'logging_level': 'DEBUG',
        'use_syslog': 'yes'
    }

    descriptors = metric_init(params)
    for d in descriptors:
        print (('%s = %s %s')
               % (d['name'], d['format'] % (d['call_back'](d['name'])),
                  d['units']))

