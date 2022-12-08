#cloud-config
package_update: false

fs_setup:
  - label: fluentd-data
    filesystem: 'ext4'
    device: '/dev/nvme1n1'
    partition: auto

mounts:
  - [ /dev/nvme1n1, /var/log/fluentd ]

write_files:
  - content: |
      local7.* -/var/log/fluentd/local7.log ; RSYSLOG_FileFormat
    path: /etc/rsyslog.d/10-local7-arcade-logging.conf

  - path: "/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json"
    permissions: "0644"
    owner: "root"
    content: |
      {
        "agent": {
          "run_as_user": "root"
        },
        "logs": {
          "logs_collected": {
            "files": {
              "collect_list": [
                {
                  "file_path": "/var/log/fluentd/local7.log",
                  "log_group_name": "{{ asg_name }}",
                  "log_stream_name": "{instance_id}/local7.log"
                }
              ]
            }
          }
        }
      }

runcmd:
  - sed -e "/imudp/s/^#//" -e "/imtcp/s/^#//" /etc/rsyslog.conf -i
  - sed -e '/log\/syslog/s/;a/;local7,a/' /etc/rsyslog.d/50-default.conf -i
  - chown syslog:adm /var/log/fluentd
  - systemctl restart rsyslog
  - wget -q https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
  - dpkg -i -E ./amazon-cloudwatch-agent.deb
  - systemctl restart amazon-cloudwatch-agent
