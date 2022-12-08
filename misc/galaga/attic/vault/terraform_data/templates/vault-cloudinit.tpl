## template: jinja
#cloud-config
package_update: false

fs_setup:
  - label: vault-data
    filesystem: 'ext4'
    device: '/dev/sdf'
    partition: auto

mounts:
  - [ sdf, /var/lib/vault ]

write_files:
  - content: |
      ui = true
      disable_mlock = true
      storage "raft" {
        path    = "/var/lib/vault"
        node_id = "{{ instance_id }}"

        retry_join {
          auto_join = "provider=aws region=${aws_region} tag_key=${retry_join_tag_key} tag_value=${retry_join_tag_value} addr_type=private_v4"

          leader_tls_servername   = "${retry_join_leader_tls_servername}"
          leader_client_cert_file = "${vault_tls_path}/${vault_tls_cert_filename}"
          leader_client_key_file  = "${vault_tls_path}/${vault_tls_key_filename}"
        }
      }

      listener "tcp" {
        address       = "0.0.0.0:${vault_api_port}"
        tls_cert_file = "${vault_tls_path}/${vault_tls_cert_filename}"
        tls_key_file  = "${vault_tls_path}/${vault_tls_key_filename}"
      }

      api_addr     = "https://{{ ds.meta_data.local_ipv4 }}:${vault_api_port}"
      cluster_addr = "https://{{ ds.meta_data.local_ipv4 }}:${vault_cluster_port}"

      log_level = "trace"

    path: /etc/vault.d/vault.hcl

  - content: complete -C "/usr/local/bin/vault" "vault"
    path: /etc/profile.d/99-vault-completion.sh

  - content: |
      #!/usr/bin/env python3
      import os
      import sys
      import hvac
      import json
      import logging
      import boto3
      from botocore.exceptions import ClientError, NoCredentialsError

      logging.basicConfig(level=logging.DEBUG, filename='/tmp/vaultbootstrap.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')


      def get_key_and_unseal(vault_url=str):
          logging.debug(f'Starting to get key on  {vault_url}')
          client = hvac.Client(url=vault_url)
          shares = 5
          threshold = 3
          if client.sys.is_initialized():
              logging.debug(f'System in initialized, exiting')
              sys.exit()
          else:
              result = client.sys.initialize(shares, threshold)
              root_token = result['root_token']
              keys = result['keys']
              unseal_response1 = client.sys.submit_unseal_key(keys[0])
              unseal_response2 = client.sys.submit_unseal_key(keys[1])
              unseal_response3 = client.sys.submit_unseal_key(keys[2])
              upload_dict = {'RootKey': root_token, 'Keys': keys}
              logging.debug(f'{upload_dict} has been created')

              with open('/home/ec2-user/vault.token.txt', 'w') as roottoken:
                  roottoken.write(root_token)

              s3 = boto3.resource('s3')
              try:
                  s3object = s3.Object('${vault_s3_buket}', 'vaultauth/${cluster_name}-keys.json')
                  d = s3object.put(Body=(bytes(json.dumps(upload_dict).encode('UTF-8'))))
                  logging.debug(d)
                  return True

              except ClientError as e:
                  logging.debug(e)
                  return False

      if __name__ == '__main__':
          get_key_and_unseal(vault_url='https://${vault_tls_url}:8200')
    path: /home/ec2-user/vault_setup.py

  - content: |
      127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4 ${vault_tls_url}
      ::1         localhost6 localhost6.localdomain6
    path: /etc/hosts

  - content: |
      export VAULT_ADDR="https://127.0.0.1:${vault_api_port}"
      export VAULT_TLS_SERVER_NAME="${retry_join_leader_tls_servername}"
      export VAULT_LICENSE_PATH=/etc/vault.d/license.hclic
      export AWS_DEFAULT_REGION="${vault_region}"
    path: /etc/profile.d/99-vault-env.sh

  - content: |
      [Unit]
      Description=Vault Keys Uploader
      After=multi-user.target

      [Service]
      Type=idle
      ExecStart=/usr/bin/python3 /home/ec2-user/vault_setup.py
      Restart=on-failure

      [Install]
      WantedBy=multi-user.target
    path: /lib/systemd/system/vault_upload.service

runcmd:
  - yum install python3 git -y
  - pip3 install hvac
  - pip3 install boto3
  - chown ec2-user:ec2-user /home/ec2-user/vault_setup.py
  - chmod u+x /home/ec2-user/vault_setup.py
  - systemctl daemon-reload
  - systemctl enable vault_upload.service
  - aws secretsmanager get-secret-value --secret-id arcade-vault/fullchain --query SecretString --region ${aws_region} --output text > /tmp/fullchain.pem
  - aws secretsmanager get-secret-value --secret-id arcade-vault/private --query SecretString --region ${aws_region} --output text > /tmp/privkey.pem
  - aws secretsmanager get-secret-value --secret-id vault/enterpriseKey --query SecretString --region ${aws_region} --output text > /tmp/license.hclic
  - cat /tmp/fullchain.pem > /etc/vault.d/tls/vaultfullchain.pem
  - cat /tmp/privkey.pem > /etc/vault.d/tls/vaultprivkey.pem
  - cat /tmp/license.hclic > /etc/vault.d/license.hclic
  - chown -R vault:vault /etc/vault.d /var/lib/vault
  - chmod 0640 /etc/vault.d/tls/*pem /etc/vault.d/*.hcl
  - chmod 0600 ${vault_tls_path}/${vault_tls_key_filename}
  - systemctl enable vault
  - systemctl start vault
  - export VAULT_TOKEN=$(cat /home/ec2-user/vault.token.txt)
  - systemctl start vault_upload
  - rm -f /tmp/*.pem
  - rm -f /tmp/license.hclic
