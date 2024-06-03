#cloud-config

package_reboot_if_required: true
package_update: true
package_upgrade: true
packages:
  - curl
# @todo(sje): figure out why changing the port isn't working
# bootcmd:
#   # Set SSH port
#   - |
#     if grep -q "^Port 22$" /etc/ssh/sshd_config; then
#       sed -i "s/Port 22/Port {{ .SSHPort }}/" /etc/ssh/sshd_config
#     else
#       echo "Port {{ .SSHPort }}" >> /etc/ssh/sshd_config
#     fi
#   - service ssh restart
runcmd:
  # Prevent login with root user
  - [
      sed,
      -i,
      -e,
      "s/^PermitRootLogin yes/PermitRootLogin no/",
      "/etc/ssh/sshd_config",
    ]
  - [service, sshd, restart]
  - [rm, -f, /root/.ssh/authorized_keys]
  # Secure UFW
  - ufw allow ssh
  - ufw enable
  - chown {{ .User }}:{{ .User }} "/home/{{ .User }}"
timezone: UTC
users:
  - default
  - name: "{{ .User }}"
    gecos: "{{ .User }}"
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true
    shell: /bin/bash
    ssh_authorized_keys:
      - "{{ .PublicKey }}"
