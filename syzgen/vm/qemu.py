
import logging
import os
import subprocess
import time
from typing import Any, Dict, List
from syzgen.config import Options
from syzgen.utils import UnusedTcpPort

from syzgen.vm import VMInstance

logger = logging.getLogger(__name__)
options = Options()


class QEMUInstance(VMInstance):
    """Start a QEMU instance
    qemu-system-x86_64 \
        -m 2G \
        -smp 2 \
        -kernel /home/wchen130/workplace/SyzGen_setup/linux-5.15/arch/x86/boot/bzImage \
        -append "console=ttyS0 root=/dev/sda net.ifnames=0" \
        -hda /home/wchen130/workplace/SyzGen_setup/debian/stretch.img \
        -chardev socket,id=SOCKSYZ,server=on,wait=off,host=localhost,port=51727 \
        -mon chardev=SOCKSYZ,mode=control \
        -device virtio-rng-pci \
        -device e1000,netdev=net0 \
        -netdev user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:10021-:22 \
        -enable-kvm \
        -display none \
        -pidfile vm.pid \
        -serial stdio \
        -cpu host,migratable=off \
        -no-reboot -name VM-0 -snapshot \
        2>&1 | tee vm.log
    """

    def __init__(
        self,
        kernel_dir: str,
        image: str,
        key: str,
        user: str="root",
        ip: str="localhost",
        ssh_port: int=0,
        gdb_port: int=0,
        memory: str="2G",
        cpu: int=2,
        enable_kvm: bool=True,
        name="VM"
    ) -> None:
        super().__init__(kernel_dir, user=user)

        self._kernel = os.path.join(
            kernel_dir, "arch", "x86", "boot", "bzImage")
        self._image = image
        self._key = key
        self._ip = ip
        self._ssh_port = ssh_port
        self._gdb_port = 1234 if options.debug_vm else gdb_port
        self._memory = memory
        self._cpu = cpu
        self._enable_kvm = enable_kvm
        self._name = name

    def copy(self) -> "QEMUInstance":
        return QEMUInstance(
            self.kernel_dir,
            self._image,
            self._key,
            user=self.user,
            ip=self._ip,
            ssh_port=0,
            gdb_port=0,
            memory=self._memory,
            cpu=self._cpu,
            enable_kvm=self._enable_kvm,
            name=self._name,
        )

    def run(self):
        self._ssh_port = self._ssh_port or UnusedTcpPort()
        self._gdb_port = self._gdb_port or UnusedTcpPort()
        cmds = [
            "qemu-system-x86_64",
            "-m", self._memory,
            "-smp", str(self._cpu),
            "-kernel", self._kernel,
            "-append", "console=ttyS0 root=/dev/sda net.ifnames=0",
            "-hda", self._image,
            "-chardev",
            f"socket,id=SOCKSYZ,server=on,wait=off,host=localhost,port={UnusedTcpPort()}",
            "-mon", "chardev=SOCKSYZ,mode=control",
            "-device", "virtio-rng-pci",
            "-device", "e1000,netdev=net0",
            "-netdev", f"user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:{self._ssh_port}-:22",
            "-display", "none",
            "-serial", "stdio",
            "-cpu", "host,migratable=off",
            "-no-reboot",
            "-name", self._name,
            "-snapshot",
            "-gdb", f"tcp::{self._gdb_port}",
        ]
        if self._enable_kvm:
            cmds.append("-enable-kvm")

        logger.debug("start the vm: %s", " ".join(cmds))
        self._process = subprocess.Popen(cmds, stdout=None if options.debug else subprocess.DEVNULL)
        self._process.communicate()

    def get_type(self) -> str:
        return "qemu"

    def get_ssh_cmd(self) -> List[str]:
        """
        Constructs the base SSH command list using instance attributes.
        """
        # Basic validation (can add more checks)
        if not self._key or not os.path.exists(self._key):
             raise FileNotFoundError(f"SSH key file not found or path invalid: {self._key}")
        if self._ssh_port <= 0 or self._ssh_port > 65535:
             raise ValueError(f"Invalid SSH port configured: {self._ssh_port}")

        cmd = [
            "ssh",
            # Specify Identity File (Private Key)
            "-i", self._key,
            # Specify Port
            "-p", str(self._ssh_port),
            # Recommended SSH Options for Automation:
            "-o", "ConnectTimeout=10",
            "-o", "ConnectionAttempts=3",
            "-o", "StrictHostKeyChecking=no", # Correct syntax
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=yes",
            "-o", "ServerAliveInterval=60",
            "-o", "LogLevel=ERROR", # Set to INFO or DEBUG for more SSH verbosity
            # User and Host
            f"{self.user}@{self._ip}",
        ]
        # logger.debug("Generated SSH command base: %s", cmd) # Uncomment for debug
        return cmd

    def get_scp_cmd(self, src, dst) -> List[str]:
        return [
            "scp",
            "-i", self._key,
            "-P", str(self._ssh_port),
            "-o", "StrictHostKeyChecking no",
            src,
            f"{self.user}@{self._ip}:{dst}"
        ]

    def wait_for_ssh(self, timeout=120):
        time.sleep(5)
        return super().wait_for_ssh(timeout=timeout)

    def suspend(self):
        pass

    def get_ip(self) -> str:
        return self._ip

    def get_debug_port(self) -> int:
        return self._gdb_port

    def get_ssh_port(self) -> int:
        return self._ssh_port

    def get_kernel(self) -> str:
        return os.path.join(self.kernel_dir, "vmlinux")

    @staticmethod
    def initialize(**kwargs):
        # Read directly from config options loaded into the global 'options' object
        # Use kwargs as overrides if provided
        ip_port = kwargs.pop("ip", "") or options.getConfigKey("ip", "localhost:22") # Expect ip:port
        user = kwargs.pop("user", "") or options.getConfigKey("user", "root")
        key = kwargs.pop("sshkey", "") or options.getConfigKey("sshkey")
        kernel_dir = kwargs.pop("kernel", "") or options.getConfigKey("kernel")
        image = kwargs.pop("image", "") or options.getConfigKey("image")

        ip = "localhost"
        port = 0 # Default to 0 so run() assigns a random one for launch mode
        if ":" in ip_port:
            try:
                ip, port_str = ip_port.split(":", 1)
                # We let run() assign the port for launch mode, so we don't use parsed port here
                # If implementing connect-only mode later, would use int(port_str)
                logger.info(f"Parsed IP {ip} from config, port will be assigned by QEMU run.")
            except ValueError:
                 logger.error(f"Invalid ip:port format in config: {ip_port}")
                 raise ValueError("Invalid ip:port format in config") from None
        else:
            ip = ip_port # Assume it's just IP if no port given
            logger.info(f"Using IP {ip} from config, port will be assigned by QEMU run.")

        if not key or not os.path.exists(key):
            logger.error(f"SSH key path missing or invalid in config: {key}")
            raise FileNotFoundError(f"SSH key ('sshkey') not found or path invalid: {key}")
        # Add checks/warnings for kernel_dir and image if needed

        # Pass potentially overridden kwargs and parsed values to __init__
        # Note: We pass ssh_port=0 to ensure run() assigns one.
        return QEMUInstance(
            kernel_dir=kernel_dir,
            image=image,
            key=key,
            user=user,
            ip=ip,
            ssh_port=0, # Force random port assignment in run() for launch mode
            # Pass other config values if needed by __init__
            memory=kwargs.pop("memory", "") or options.getConfigKey("memory", "2G"),
            cpu=kwargs.pop("cpu", 0) or options.getConfigKey("cpu", 2),
            enable_kvm=kwargs.pop("enable_kvm", None) or options.getConfigKey("enable_kvm", True),
            name=kwargs.pop("name", "") or options.getConfigKey("name", "VM"),
            **kwargs # Pass any remaining kwargs
        )
    def genSyzConfig(self, num_cpu=2, num_vm=1, **kwargs) -> Dict[str, Any]:
        return {
            "sshkey": options.getConfigKey("sshkey"),
            "ssh_user": self.user,
            "kernel_obj": options.getConfigKey("kernel"),
            "image": options.getConfigKey("image"),
            "vm": {
                "count": num_vm,
                "cpu": num_cpu,
                "mem": 2048,
                "cmdline": "net.ifnames=0",
                "kernel": os.path.join(options.getConfigKey("kernel"), "arch", "x86", "boot", "bzImage"),
            }
        }


def TestQEMUInstance():
    inst = QEMUInstance(
        options.getConfigKey("kernel"),
        options.getConfigKey("image"),
        options.getConfigKey("sshkey"),
    )
    with inst:
        # inst.start()
        inst.wait_for_ssh()
        inst.copy_file("invalid_prog.syz", "/invalid_prog.syz")
        inst.copy_file("valid_prog.syz", "/valid_prog.syz")
        # inst.copy_file("test.syz", "/test.syz")
        inst.copy_file(
            os.path.join(options.getConfigKey("syzkaller"),
                         "bin", "linux_amd64", "syz-run"),
            "/syz-run"
        )
        inst.copy_file(
            os.path.join(options.getConfigKey("syzkaller"),
                         "bin", "linux_amd64", "syz-executor"),
            "/syz-executor"
        )
        ret = inst.run_cmd([
            "/syz-run",
            "-executor=/syz-executor",
            "-vv=100",
            "-cover",
            "-collide=false",
            "-threaded=false",
            "-output=true",
            # "-debug",
            # "-coverfile=1",
            "-syscall=ioctl\\$ppp_Group4004743d_0",
            "/invalid_prog.syz",
            "/valid_prog.syz",
        ], enable_stderr=True)
        if b"sys-run: Succeed!" in ret.stderr:
            logger.debug("Succeed!!!")
        else:
            logger.debug("Failed!!!")
