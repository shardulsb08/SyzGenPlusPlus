import os
import glob

# List of config strings to check
config_strings = [
    "CONFIG_FAILSLAB", "CONFIG_FAIL_PAGE_ALLOC",
    "CONFIG_FAIL_MAKE_REQUEST", "CONFIG_FAIL_IO_TIMEOUT", "CONFIG_FAIL_FUTEX",
    "CONFIG_DEBUG_VM", "CONFIG_REFCOUNT_FULL", "CONFIG_FORTIFY_SOURCE", "CONFIG_HARDENED_USERCOPY",
    "CONFIG_LOCKUP_DETECTOR", "CONFIG_SOFTLOCKUP_DETECTOR", "CONFIG_HARDLOCKUP_DETECTOR",
    "CONFIG_DETECT_HUNG_TASK", "CONFIG_WQ_WATCHDOG",
    "CONFIG_DEBUG_KMEMLEAK",
    "CONFIG_KALLSYMS_ALL"
]

# Base path where the config files are located
base_path = "linux-distro/linux-6.14-*"
config_files = glob.glob(os.path.join(base_path, ".config"))

# Dictionary to store results
results = {}

for config_file in config_files:
    present_configs = []
    with open(config_file, 'r') as file:
        contents = file.read()
        for cfg in config_strings:
            if cfg in contents:
                present_configs.append(cfg)
    results[config_file] = present_configs

# Display results
for config_file, configs in results.items():
    print(f"{config_file}:")
    for cfg in configs:
        print(f"  {cfg}")
    print()

