#cloud-config

package_reboot_if_required: true
package_update: true
package_upgrade: true
packages:
  - curl
bootcmd:
  # Set SSH port
  - |
    if grep -q "^Port 22$" /etc/ssh/sshd_config; then
      sed -i "s/Port 22/Port {{ .SSHPort }}/" /etc/ssh/sshd_config
    else
      echo "Port {{ .SSHPort }}" >> /etc/ssh/sshd_config
    fi
  - service ssh restart
timezone: UTC
