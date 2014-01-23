import paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(
    paramiko.AutoAddPolicy())
ssh.connect('ceph-node1', username='ceph', password='lol')
stdin, stdout, stderr = ssh.exec_command("uptime")
type(stdin)
stdout.readlines()

stdin, stdout, stderr = ssh.exec_command("uptime")
stdout.readlines()