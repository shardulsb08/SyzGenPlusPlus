
import argparse
import logging
import multiprocessing
import os
import subprocess
import shutil
import re # Needed for parsing

logger = logging.getLogger("syzgen")

def parse_kconfig_file(filepath):
    """Parses a kernel config file fragment.

    Args:
        filepath (str): Path to the kconfig file fragment.

    Returns:
        dict: A dictionary where keys are CONFIG_ names (str) and
              values are their corresponding values (str, e.g., 'y', 'n', '100').
              Returns an empty dict if the file doesn't exist or is empty.
    """
    config_settings = {}
    if not os.path.exists(filepath):
        print(f"Warning: Kconfig fragment file not found: {filepath}")
        return config_settings
    if not os.path.isfile(filepath):
        print(f"Warning: Kconfig fragment path is not a file: {filepath}")
        return config_settings

    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    # Handle '# CONFIG_FOO is not set' - treat as disable
                    match_not_set = re.match(r'^#\s+(CONFIG_[A-Za-z0-9_]+)\s+is\s+not\s+set', line)
                    if match_not_set:
                        config_name = match_not_set.group(1)
                        config_settings[config_name] = 'n' # Treat 'not set' as 'n'
                    continue

                # Match 'CONFIG_FOO=y' or 'CONFIG_BAR=123' or 'CONFIG_BAZ="string"'
                match_set = re.match(r'^(CONFIG_[A-Za-z0-9_]+)=(.*)', line)
                if match_set:
                    config_name = match_set.group(1)
                    value = match_set.group(2).strip()
                    # Remove quotes from string values if present
                    if len(value) > 1 and value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    config_settings[config_name] = value

    except IOError as e:
        print(f"Warning: Could not read kconfig fragment file {filepath}: {e}")

    return config_settings

def tweak_config(filepath, enables, disables):
    with open(filepath, "r") as fp:
        cont = fp.read()
        for each in enables:
            cont = cont.replace(f"# {each} is not set", f"{each}=y")
        for each in disables:
            cont = cont.replace(f"{each}=y", f"# {each} is not set")
    with open(filepath, "w") as fp:
        fp.write(cont)


def get_def_config(source_dir, fuzzing=False):
    subprocess.run(["make", "defconfig"], cwd=source_dir, check=True)
    subprocess.run(["make", "kvm_guest.config"], cwd=source_dir, check=True)

    # tweak config
    enables = [
        "CONFIG_NAMESPACES",
        "CONFIG_DEBUG_INFO",
        "CONFIG_CONFIGFS_FS",
        "CONFIG_SECURITYFS",
        # for kprobes and ftrace
        "CONFIG_FUNCTION_TRACER",
        # additonal module to test
        # ppp also has suboptions
        "CONFIG_PPP",
    ]

    if fuzzing:
        enables.append("CONFIG_KCOV")
        enables.append("CONFIG_KASAN")
        # It is a suboption and not sure we need to enable it
        # "CONFIG_KASAN_INLINE"

    disables = [
        "CONFIG_RANDOMIZE_BASE",
    ]
    tweak_config(os.path.join(source_dir, ".config"), enables, disables)
    subprocess.run(["make", "olddefconfig"], cwd=source_dir, check=True)


def get_config(source_dir, config_source, fuzzing=False, syzkaller_config_path="/build_input/kernel_syskaller.config"):
    """
    Gets the kernel config file, applies tweaks using scripts/config,
    and runs make olddefconfig. Handles base tweaks and specific
    fuzzing tweaks from a file.
    """
    config_target = os.path.join(source_dir, ".config")
    print(f"Processing config source: {config_source}")

    # --- Step 1: Get the base config file ---
    if config_source.startswith("http://") or config_source.startswith("https://"):
        print(f"Downloading config from URL: {config_source}")
        try:
            with open(config_target, "w") as fp:
                subprocess.run(["curl", "-fL", config_source], stdout=fp, check=True)
            print(f"Successfully downloaded config to {config_target}")
        except subprocess.CalledProcessError as e:
            print(f"Error downloading config from {config_source}: {e}")
            if os.path.exists(config_target): os.remove(config_target)
            raise
        except Exception as e:
            print(f"An unexpected error occurred during download: {e}")
            if os.path.exists(config_target): os.remove(config_target)
            raise
    else:
        print(f"Copying config from local file: {config_source}")
        if not os.path.exists(config_source):
            raise FileNotFoundError(f"Local config file not found: {config_source}")
        if not os.path.isfile(config_source):
            raise IsADirectoryError(f"Local config source is not a file: {config_source}")
        try:
            shutil.copyfile(config_source, config_target)
            print(f"Successfully copied config to {config_target}")
        except Exception as e:
            print(f"Error copying config file from {config_source} to {config_target}: {e}")
            if os.path.exists(config_target): os.remove(config_target)
            raise

    if not os.path.exists(config_target):
         raise FileNotFoundError(f"Base config file {config_target} was not created successfully.")

    # --- Step 2: Prepare and apply config tweaks using scripts/config ---
    print(f"Tweaking config file: {config_target}")
    config_script_relative = os.path.join("scripts", "config") # Path relative to kernel source root
    config_target_relative = ".config"                        # Path relative to kernel source root

    config_script_full_path_check = os.path.join(source_dir, config_script_relative)
    if not os.path.exists(config_script_full_path_check):
        # This check should ideally be in download_linux *before* calling get_config
        raise FileNotFoundError(f"Kernel config script not found at: {config_script_full_path_check}. "
                                f"Ensure kernel source is properly extracted in {source_dir}.")
    # Optional: Check execute permissions here if needed later
    # if not os.access(config_script_full_path_check, os.X_OK):
    #     raise PermissionError(f"Execute permission missing for {config_script_full_path_check}")

    # Base enables/disables lists remain the same
    base_enables = [
        "CONFIG_FUNCTION_TRACER",
        "CONFIG_KPROBES",
    ]
    base_disables = [
        "CONFIG_MODULE_FORCE_LOAD", "CONFIG_MODVERSIONS", "CONFIG_ASM_MODVERSIONS",
        "CONFIG_MODULE_SRCVERSION_ALL", "CONFIG_MODULE_SIG", "CONFIG_SECURITY_LOCKDOWN_LSM",
    ]
    non_fuzzing_disables = [
        # KCOV
        "CONFIG_KCOV", "CONFIG_KCOV_ENABLE_COMPARISONS", "CONFIG_KCOV_INSTRUMENT_ALL",
        # KASAN
        "CONFIG_KASAN", "CONFIG_KASAN_EXTRA", "CONFIG_KASAN_INLINE", "CONFIG_KASAN_OUTLINE",
        # UBSAN
        "CONFIG_UBSAN", "CONFIG_UBSAN_SANITIZE_ALL",
        # Debugging features
        "CONFIG_PROVE_LOCKING", "CONFIG_DEBUG_ATOMIC_SLEEP", "CONFIG_DEBUG_PER_CPU_MAPS",
        "CONFIG_DEBUG_TIMEKEEPING", "CONFIG_DEBUG_RT_MUTEXES", "CONFIG_DEBUG_SPINLOCK",
        "CONFIG_DEBUG_MUTEXES", "CONFIG_DEBUG_WW_MUTEX_SLOWPATH", "CONFIG_DEBUG_RWSEMS",
        "CONFIG_DEBUG_LOCK_ALLOC", "CONFIG_LOCKDEP", "CONFIG_TRACE_IRQFLAGS",
        "CONFIG_TRACE_IRQFLAGS_NMI", "CONFIG_PROVE_RCU", "CONFIG_PREEMPTIRQ_TRACEPOINTS",
        # Other
        "CONFIG_NET_SCHED",
        # New additions
        "CONFIG_DEBUG_INFO", "CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT", "CONFIG_DEBUG_INFO_DWARF4",
        "CONFIG_FAULT_INJECTION", "CONFIG_FAILSLAB", "CONFIG_FAIL_PAGE_ALLOC",
        "CONFIG_FAIL_MAKE_REQUEST", "CONFIG_FAIL_IO_TIMEOUT", "CONFIG_FAIL_FUTEX",
        "CONFIG_DEBUG_VM", "CONFIG_REFCOUNT_FULL", "CONFIG_FORTIFY_SOURCE", "CONFIG_HARDENED_USERCOPY",
        "CONFIG_LOCKUP_DETECTOR", "CONFIG_SOFTLOCKUP_DETECTOR", "CONFIG_HARDLOCKUP_DETECTOR",
        "CONFIG_DETECT_HUNG_TASK", "CONFIG_WQ_WATCHDOG",
        "CONFIG_DEBUG_KMEMLEAK",
        "CONFIG_KALLSYMS_ALL",
    ]

    # *** FIX: Use relative paths in cmd_args ***
    cmd_args = [config_script_relative, "--file", config_target_relative]
    syz_settings = {}

    if fuzzing:
        # ... (logic to parse syz_settings and add --enable/--disable/--set-val to cmd_args is correct) ...
        print(f"Applying fuzzing-specific tweaks from: {syzkaller_config_path}")
        syz_settings = parse_kconfig_file(syzkaller_config_path)
        if not syz_settings:
             print("Warning: No settings found or loaded from Syzkaller config file.")
        for config in base_enables: cmd_args.extend(["--enable", config])
        for config in base_disables: cmd_args.extend(["--disable", config])
        for config, value in syz_settings.items():
            if value == 'y': cmd_args.extend(["--enable", config])
            elif value == 'n': cmd_args.extend(["--disable", config])
            else: cmd_args.extend(["--set-val", config, str(value)])

    else: # Not fuzzing
        # ... (logic to determine all_disables and add --enable/--disable to cmd_args is correct) ...
        print("Applying standard (non-fuzzing) tweaks.")
        for config in base_enables: cmd_args.extend(["--enable", config])
        all_disables = base_disables + non_fuzzing_disables
        print(f"Disabling {len(set(all_disables))} options for non-fuzzing build.")
        for config in sorted(list(set(all_disables))): cmd_args.extend(["--disable", config])


    # Execute scripts/config using relative paths WITH cwd set
    print(f"Running: {' '.join(cmd_args)} (in CWD: {source_dir})") # Modified print
    try:
        # *** The actual call: uses relative executable/file paths + cwd ***
        comp_proc = subprocess.run(cmd_args, cwd=source_dir, check=True, capture_output=True, text=True)
        print("'scripts/config' completed successfully.")
    except FileNotFoundError as e:
         # Check permissions only if FileNotFoundError occurs (less likely)
         config_script_full_path = os.path.join(source_dir, config_script_relative)
         if os.path.exists(config_script_full_path) and not os.access(config_script_full_path, os.X_OK):
             print(f"PermissionError: Execute permission denied for {config_script_full_path}")
             # You might want to raise a PermissionError here instead or handle it
         else:
             # Print the original error if it's not a permission issue
             print(f"ERROR running 'scripts/config': {e}")
             print(f"Tried to run command: {' '.join(e.args)}") # Show args from exception
             print(f"In working directory: {source_dir}")
         raise # Re-raise original or permission error
    except subprocess.CalledProcessError as e:
        # ... (Existing CalledProcessError handling is good) ...
        print(f"Error running 'scripts/config': {e}")
        print(f"Command: {' '.join(e.cmd)}")
        print(f"Return Code: {e.returncode}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
        raise

    # --- Step 3: Run make olddefconfig ---
    # This part correctly uses cwd=source_dir and simple command "make"
    print(f"Running 'make olddefconfig' in {source_dir}")
    # ... (make olddefconfig call remains the same) ...
    try:
        comp_proc = subprocess.run(["make", "olddefconfig"], cwd=source_dir, check=True, capture_output=True, text=True)
        print("'make olddefconfig' completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error running 'make olddefconfig': {e}")
        print(f"Command: {' '.join(e.cmd)}")
        print(f"Return Code: {e.returncode}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
        raise
    except FileNotFoundError:
        print("FATAL: 'make' command not found. Please ensure build tools are installed.")
        raise

def download_linux(out_dir, version, build=False, config_url="", syz_config="/build_input/kernel_syskaller.config"):
    try:
        os.mkdir(out_dir)
    except:
        pass

    url = (
        "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/"
        f"linux.git/snapshot/linux-{version}.tar.gz"
    )
    outfile = os.path.join(out_dir, f"linux-{version}.tar.gz")
    # Download the kernel
    if not os.path.exists(outfile):
        cmds = [
            "wget",
            url,
            "-O",
            outfile,
        ]
        subprocess.run(cmds, check=True)
    # Untar the file
    kernelForFuzzing = os.path.join(out_dir, f"linux-{version}-fuzz")
    rawKernel = os.path.join(out_dir, f"linux-{version}-raw")
    for out in [kernelForFuzzing, rawKernel]:
        if not os.path.exists(out):
            os.mkdir(out)
            cmds = [
                "tar",
                "-xf",
                outfile,
                "-C", out,
                "--strip-components=1",
            ]
            subprocess.run(cmds, check=True)

        if config_url:
            get_config(out, config_url, out == kernelForFuzzing, syzkaller_config_path=syz_config)
        else:
            get_def_config(out, out == kernelForFuzzing)
        if build:
            cpu_cores = multiprocessing.cpu_count()
            print("having %s cpu cores" % cpu_cores)
            subprocess.run(["make", f"-j{min(32, cpu_cores)}"], cwd=out, check=True)


def clean(out_dir, version):
    kernelForFuzzing = os.path.join(out_dir, f"linux-{version}-fuzz")
    rawKernel = os.path.join(out_dir, f"linux-{version}-raw")
    for out in [kernelForFuzzing, rawKernel]:
        if os.path.exists(out):
            subprocess.run(["make", "clean"], cwd=out, check=True)

# python scripts/download.py -c "https://syzkaller.appspot.com/text?tag=KernelConfig&x=dd7c9a79dfcfa205" --build -v 5.15


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="main")
    parser.add_argument("-v", "--version", required=True,
                        help="kernel version")
    parser.add_argument("-o", "--out", default="linux-distro",
                        help="output dir to store kernel source code (default: ./linux-distro)")
    parser.add_argument("-c", "--config", default="", help="url to .config")
    parser.add_argument("--build", action="store_true",
                        default=False, help="build kernel")
    parser.add_argument("--clean", action="store_true",
                        default=False, help="clean kernel binary")
    parser.add_argument("--syz-config", default="/build_input/kernel_syskaller.config",
                        help="Path to Syzkaller kconfig fragment (used if building for fuzzing)")


    args = parser.parse_args()
    if args.clean:
        clean(args.out, args.version)
    else:
        download_linux(args.out, args.version, args.build, args.config, args.syz_config)
