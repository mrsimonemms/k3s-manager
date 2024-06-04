#cloud-config

package_reboot_if_required: true
package_update: true
package_upgrade: true
packages:
  - curl
runcmd:
  - [service, sshd, restart]
  - [rm, -f, /root/.ssh/authorized_keys]
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
write_files:
  - path: /etc/ssh/sshd_config.d/ssh.conf
    content: |
      PasswordAuthentication no
      PermitRootLogin no
      Port {{ .SSHPort }}
