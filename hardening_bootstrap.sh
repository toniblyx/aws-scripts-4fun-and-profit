#!/bin/bash -e
# Bastion Bootstrapping
# authors: tonynv@amazon.com, sancard@amazon.com, ianhill@amazon.com
# NOTE: This requires GNU getopt. On Mac OS X and FreeBSD you must install GNU getopt and mod the checkos function so that it's supported
# Adapted for hardening other than just bastion by toni.delafuente@alfresco.com
# Configuration
PROGRAM='Linux Hardening'
##################################### Functions Definitions
function checkos () {
    platform='unknown'
    unamestr=`uname`
    if [[ "${unamestr}" == 'Linux' ]]; then
        platform='linux'
    else
        echo "[WARNING] This script is not supported on MacOS or freebsd"
        exit 1
    fi
    echo "${FUNCNAME[0]} Ended"
}
function setup_environment_variables() {
  REGION=$(curl -sq http://169.254.169.254/latest/meta-data/placement/availability-zone/)
  #ex: us-east-1a => us-east-1
  REGION=${REGION: :-1}
  ETH0_MAC=$(/sbin/ip link show dev eth0 | /bin/egrep -o -i 'link/ether\ ([0-9a-z]{2}:){5}[0-9a-z]{2}' | /bin/sed -e 's,link/ether\ ,,g')
  userdata_file_path="/var/lib/cloud/instance/user-data.txt"
  INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
  EIP_LIST=$(grep EIP_LIST ${userdata_file_path} | sed -e 's/EIP_LIST=//g' -e 's/\"//g')
  LOCAL_IP_ADDRESS=$(curl -sq 169.254.169.254/latest/meta-data/network/interfaces/macs/${ETH0_MAC}/local-ipv4s/)
  CWG=$(grep CLOUDWATCHGROUP ${userdata_file_path} | sed 's/CLOUDWATCHGROUP=//g')
  # LOGGING CONFIGURATION
  BASTION_MNT="/var/log/bastion"
  BASTION_LOG="bastion.log"
  echo "Setting up bastion session log in ${BASTION_MNT}/${BASTION_LOG}"
  mkdir -p ${BASTION_MNT}
  BASTION_LOGFILE="${BASTION_MNT}/${BASTION_LOG}"
  BASTION_LOGFILE_SHADOW="${BASTION_MNT}/.${BASTION_LOG}"
  touch ${BASTION_LOGFILE}
  ln ${BASTION_LOGFILE} ${BASTION_LOGFILE_SHADOW}
  mkdir -p /usr/bin/bastion
  touch /tmp/messages
  chmod 770 /tmp/messages
  log_shadow_file_location="${bastion_mnt}/.${bastion_log}"
  export REGION ETHO_MAC EIP_LIST CWG BASTION_MNT BASTION_LOG BASTION_LOGFILE BASTION_LOGFILE_SHADOW \
          LOCAL_IP_ADDRESS INSTANCE_ID
}
function verify_dependencies(){
  if [[ "a$(which aws)" == "a" ]]; then
    pip install awscli
  fi
  echo "${FUNCNAME[0]} Ended"
}
function usage() {
    echo "$0 <usage>"
    echo " "
    echo "options:"
    echo -e "--help \t Show options for this script"
    echo -e "--tcp-forwarding \t Enable or Disable TCP Forwarding"
    echo -e "--x11-forwarding \t Enable or Disable X11 Forwarding"
}
function chkstatus () {
    if [ $? -eq 0 ]
    then
        echo "Script [PASS]"
    else
        echo "Script [FAILED]" >&2
        exit 1
    fi
}

function osrelease () {
    OS=`cat /etc/os-release | grep '^NAME=' |  tr -d \" | sed 's/\n//g' | sed 's/NAME=//g'`
    if [ "${OS}" == "Ubuntu" ]; then
        echo "Ubuntu"
    elif [ "${OS}" == "Amazon Linux AMI" ] || [ "${OS}" == "Amazon Linux" ]; then
        echo "AMZN"
    elif [ "${OS}" == "CentOS Linux" ]; then
        echo "CentOS"
    else
        echo "Operating System Not Found"
    fi
    echo "${FUNCNAME[0]} Ended" >> /var/log/cfn-init.log
}

function harden_ssh_security () {
  # Allow ec2-user only to access this folder and its content
  #chmod -R 770 /var/log/bastion
  #setfacl -Rdm other:0 /var/log/bastion
  # Make OpenSSH execute a custom script on logins
  echo -e "\nForceCommand /usr/bin/bastion/shell" >> /etc/ssh/sshd_config

  cat <<'EOF' >> /usr/bin/bastion/shell
    bastion_mnt="/var/log/bastion"
    bastion_log="bastion.log"
    # Check that the SSH client did not supply a command. Only SSH to instance should be allowed.
    export Allow_SSH="ssh"
    export Allow_SCP="scp"
    if [[ -z $SSH_ORIGINAL_COMMAND ]] || [[ $SSH_ORIGINAL_COMMAND =~ ^$Allow_SSH ]] || [[ $SSH_ORIGINAL_COMMAND =~ ^$Allow_SCP ]]; then
    #Allow ssh to instance and log connection
      if [ -z "$SSH_ORIGINAL_COMMAND" ]; then
          /bin/bash
          exit 0
      else
          $SSH_ORIGINAL_COMMAND
      fi
      log_file=$(echo "$log_shadow_file_location")
      DATE_TIME_WHOAMI="`whoami`:`date "+%Y-%m-%d %H:%M:%S"`"
      LOG_ORIGINAL_COMMAND=`echo "$DATE_TIME_WHOAMI:$SSH_ORIGINAL_COMMAND"`
      echo "$LOG_ORIGINAL_COMMAND" >> "${bastion_mnt}/${bastion_log}"
      log_dir="/var/log/bastion/"
    else
      # The "script" program could be circumvented with some commands
      # (e.g. bash, nc). Therefore, I intentionally prevent users
      # from supplying commands.
      echo "This bastion supports interactive sessions only. Do not supply a command"
      exit 1
    fi
EOF

  # Make the custom script executable
  chmod a+x /usr/bin/bastion/shell
  release=$(osrelease)
  if [ "${release}" == "CentOS" ]; then
      semanage fcontext -a -t ssh_exec_t /usr/bin/bastion/shell
  fi
  echo "${FUNCNAME[0]} Ended"
}

function amazon_os () {
  echo "${FUNCNAME[0]} Started"
  chown root:ec2-user /usr/bin/script
  service sshd restart
  echo -e "\nDefaults env_keep += \"SSH_CLIENT\"" >>/etc/sudoers
  cat <<'EOF' >> /etc/bashrc
  #Added by linux bastion bootstrap
  declare -rx IP=$(echo $SSH_CLIENT | awk '{print $1}')
EOF
  echo " declare -rx BASTION_LOG=${BASTION_MNT}/${BASTION_LOG}" >> /etc/bashrc

  cat <<'EOF' >> /etc/bashrc
  declare -rx PROMPT_COMMAND='history -a >(logger -t "ON: $(date)   [FROM]:${IP}   [USER]:${USER}   [PWD]:${PWD}" -s 2>>${BASTION_LOG})'
EOF
  chown root:ec2-user  ${BASTION_MNT}
  chown root:ec2-user  ${BASTION_LOGFILE}
  chown root:ec2-user  ${BASTION_LOGFILE_SHADOW}
  chmod 662 ${BASTION_LOGFILE}
  chmod 662 ${BASTION_LOGFILE_SHADOW}
  chattr +a ${BASTION_LOGFILE}
  chattr +a ${BASTION_LOGFILE_SHADOW}
  touch /tmp/messages
  chown root:ec2-user /tmp/messages
  #Run security updates
  cat <<'EOF' >> ~/mycron
  0 0 * * * yum -y update --security
EOF
  crontab ~/mycron
  rm ~/mycron
  echo "${FUNCNAME[0]} Ended"
}

function request_eip() {
  # Is the already-assigned Public IP an elastic IP?
  query_assigned_public_ip
  set +e
  determine_eip_assc_status ${PUBLIC_IP_ADDRESS}
  set -e
  if [[ ${eip_associated} -ne 1 ]]; then
    echo "The Public IP address associated with eth0 (${PUBLIC_IP_ADDRESS}) is already an Elastic IP. Not proceeding further."
    exit 1
  fi
  EIP_ARRAY=(${EIP_LIST//,/ })
  eip_assigned_count=0
  for eip in "${EIP_ARRAY[@]}"; do
    if [ "${eip}" == "Null" ]; then
      echo "Detected a NULL Value, moving on."
      continue
    fi
    # Determine if the EIP has already been assigned.
    set +e
    determine_eip_assc_status ${eip}
    set -e
    if [[ ${eip_associated} -eq 0 ]]; then
      echo "Elastic IP [${eip}] already has an association. Moving on."
      let eip_assigned_count+=1
      if [ "${eip_assigned_count}" -eq "${#EIP_ARRAY[@]}" ]; then
        echo "All of the stack EIPs have been assigned (${eip_assigned_count}/${#EIP_ARRAY[@]}). I can't assign anything else. Exiting."
        exit 1
      fi
      continue
    fi
    determine_eip_allocation ${eip}
    # Attempt to assign EIP to the ENI.
    set +e
    aws ec2 associate-address --instance-id ${INSTANCE_ID} --allocation-id  ${eip_allocation} --region ${REGION}
    rc=$?
    set -e
    if [ ${rc} -ne 0 ]; then
      let eip_assigned_count+=1
      continue
    else
      echo "The newly-assigned EIP is ${eip}. It is mapped under EIP Allocation ${eip_allocation}"
      break
    fi
  done
  echo "${FUNCNAME[0]} Ended"
}
function query_assigned_public_ip() {
  # Note: ETH0 Only.
  # - Does not distinquish between EIP and Standard IP. Need to cross-ref later.
  echo "Querying the assigned public IP"
  PUBLIC_IP_ADDRESS=$(curl -sq 169.254.169.254/latest/meta-data/public-ipv4/${ETH0_MAC}/public-ipv4s/)
}
function determine_eip_assc_status(){
  # Is the provided EIP associated?
  # Also determines if an IP is an EIP.
  # 0 => true
  # 1 => false
  echo "Determining EIP Association Status for [${1}]"
  set +e
  aws ec2 describe-addresses --public-ips ${1} --output text --region ${REGION} 2>/dev/null  | grep -o -i eipassoc -q
  rc=$?
  set -e
  if [[ ${rc} -eq 1 ]]; then
    eip_associated=1
  else
    eip_associated=0
  fi
}
function determine_eip_allocation(){
  echo "Determining EIP Allocation for [${1}]"
  resource_id_length=$(aws ec2 describe-addresses --public-ips ${1} --output text --region ${REGION} | awk {'print $2'} | sed 's/.*eipalloc-//')
  if [ "${#resource_id_length}" -eq 17 ]; then
      eip_allocation=$(aws ec2 describe-addresses --public-ips ${1} --output text --region ${REGION}| egrep 'eipalloc-([a-z0-9]{17})' -o)
  else
      eip_allocation=$(aws ec2 describe-addresses --public-ips ${1} --output text --region ${REGION}| egrep 'eipalloc-([a-z0-9]{8})' -o)
  fi
}
function prevent_process_snooping() {
  # Prevent bastion host users from viewing processes owned by other users.
  mount -o remount,rw,hidepid=2 /proc
  awk '!/proc/' /etc/fstab > temp && mv temp /etc/fstab
  echo "proc /proc proc defaults,hidepid=2 0 0" >> /etc/fstab
  echo "${FUNCNAME[0]} Ended"
}

# function below address hardening for k8s and docker following their CIS benchmark
function harden_workernode_kubernetes() {
  KUBELET_SERVICE_FILE="/etc/systemd/system/kubelet.service"
  # K8s CIS benchmark 2.1.1
  #sed -i 's/allow-privileged=true/allow-privileged=false/g' $KUBELET_SERVICE_FILE
  # K8s CIS benchmark 2.1.5
  sed -i '/--anonymous-auth=false \\/a \ \ --read-only-port=0 \\' $KUBELET_SERVICE_FILE

  # K8s CIS benchmark 2.1.6
  sed -i '/--anonymous-auth=false \\/a \ \ --streaming-connection-idle-timeout=5m \\' $KUBELET_SERVICE_FILE

  # K8s CIS benchmark 2.1.7
  sed -i '/--anonymous-auth=false \\/a \ \ --protect-kernel-defaults=true \\' $KUBELET_SERVICE_FILE

  # K8s CIS benchmark 2.1.9
  sed -i '/--anonymous-auth=false \\/a \ \ --keep-terminated-pod-volumes=false \\' $KUBELET_SERVICE_FILE

  # K8s CIS benchmark 2.1.11
  sed -i '/--anonymous-auth=false \\/a \ \ --event-qps=0 \\' $KUBELET_SERVICE_FILE

  # K8s CIS benchmark 2.1.13
  sed -i '/--anonymous-auth=false \\/a \ \ --cadvisor-port=0 \\' $KUBELET_SERVICE_FILE

  # K8s CIS benchmark 2.2.1
  chmod 644 $KUBELET_SERVICE_FILE

  # K8s CIS benchmark 2.2.2
  chown root:root $KUBELET_SERVICE_FILE
  # restart service
  systemctl daemon-reload
  systemctl restart kubelet.service

  # get auditd configuration and apply (it audits dockerd and kubelet processes)
  # /etc/audit/rules.d/audit.rules
  cat <<'EOF' >> /etc/audit/rules.d/audit.rules
  # Remove any existing rules
  -D

  # Buffer Size
  ## Feel free to increase this if the machine panic's
  -b 8192

  # Failure Mode
  ## Possible values: 0 (silent), 1 (printk, print a failure message), 2 (panic, halt the system)
  -f 1

  # Ignore errors
  ## e.g. caused by users or files not found in the local environment
  -i

  # Self Auditing ---------------------------------------------------------------

  ## Audit the audit logs
  ### Successful and unsuccessful attempts to read information from the audit records
  -w /var/log/audit/ -k auditlog

  ## Auditd configuration
  ### Modifications to audit configuration that occur while the audit collection functions are operating
  -w /etc/audit/ -p wa -k auditconfig
  -w /etc/libaudit.conf -p wa -k auditconfig
  -w /etc/audisp/ -p wa -k audispconfig

  ## Monitor for use of audit management tools
  -w /sbin/auditctl -p x -k audittools
  -w /sbin/auditd -p x -k audittools

  # Filters ---------------------------------------------------------------------

  ### We put these early because audit is a first match wins system.

  ## Ignore SELinux AVC records
  -a always,exclude -F msgtype=AVC

  ## Ignore current working directory records
  -a always,exclude -F msgtype=CWD

  ## Ignore EOE records (End Of Event, not needed)
  -a always,exclude -F msgtype=EOE

  ## Cron jobs fill the logs with stuff we normally don't want (works with SELinux)
  -a never,user -F subj_type=crond_t
  -a exit,never -F subj_type=crond_t

  ## This prevents chrony from overwhelming the logs
  -a never,exit -F arch=b64 -S adjtimex -F auid=unset -F uid=_chrony -F subj_type=chronyd_t

  ## This is not very interesting and wastes a lot of space if the server is public facing
  -a always,exclude -F msgtype=CRYPTO_KEY_USER

  ## VMWare tools
  -a exit,never -F arch=b32 -S fork -F success=0 -F path=/usr/lib/vmware-tools -F subj_type=initrc_t -F exit=-2
  -a exit,never -F arch=b64 -S fork -F success=0 -F path=/usr/lib/vmware-tools -F subj_type=initrc_t -F exit=-2

  ### High Volume Event Filter (especially on Linux Workstations)
  -a exit,never -F arch=b32 -F dir=/dev/shm -k sharedmemaccess
  -a exit,never -F arch=b64 -F dir=/dev/shm -k sharedmemaccess
  -a exit,never -F arch=b32 -F dir=/var/lock/lvm -k locklvm
  -a exit,never -F arch=b64 -F dir=/var/lock/lvm -k locklvm

  ## More information on how to filter events
  ### https://access.redhat.com/solutions/2482221

  # Rules -----------------------------------------------------------------------

  ## Kernel parameters
  -w /etc/sysctl.conf -p wa -k sysctl

  ## Kernel module loading and unloading
  -a always,exit -F perm=x -F auid!=-1 -F path=/sbin/insmod -k modules
  -a always,exit -F perm=x -F auid!=-1 -F path=/sbin/modprobe -k modules
  -a always,exit -F perm=x -F auid!=-1 -F path=/sbin/rmmod -k modules
  -a always,exit -F arch=b64 -S finit_module -S init_module -S delete_module -F auid!=-1 -k modules
  -a always,exit -F arch=b32 -S finit_module -S init_module -S delete_module -F auid!=-1 -k modules
  ## Modprobe configuration
  -w /etc/modprobe.conf -p wa -k modprobe

  ## KExec usage (all actions)
  -a always,exit -F arch=b64 -S kexec_load -k KEXEC
  -a always,exit -F arch=b32 -S sys_kexec_load -k KEXEC

  ## Special files
  -a exit,always -F arch=b32 -S mknod -S mknodat -k specialfiles
  -a exit,always -F arch=b64 -S mknod -S mknodat -k specialfiles

  ## Mount operations (only attributable)
  -a always,exit -F arch=b64 -S mount -S umount2 -F auid!=-1 -k mount
  -a always,exit -F arch=b32 -S mount -S umount -S umount2 -F auid!=-1 -k mount

  # Change swap (only attributable)
  -a always,exit -F arch=b64 -S swapon -S swapoff -F auid!=-1 -k swap
  -a always,exit -F arch=b32 -S swapon -S swapoff -F auid!=-1 -k swap

  ## Time
  -a exit,always -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k time
  -a exit,always -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time
  ### Local time zone
  -w /etc/localtime -p wa -k localtime

  ## Stunnel
  -w /usr/sbin/stunnel -p x -k stunnel

  ## Cron configuration & scheduled jobs
  -w /etc/cron.allow -p wa -k cron
  -w /etc/cron.deny -p wa -k cron
  -w /etc/cron.d/ -p wa -k cron
  -w /etc/cron.daily/ -p wa -k cron
  -w /etc/cron.hourly/ -p wa -k cron
  -w /etc/cron.monthly/ -p wa -k cron
  -w /etc/cron.weekly/ -p wa -k cron
  -w /etc/crontab -p wa -k cron
  -w /var/spool/cron/crontabs/ -k cron

  ## User, group, password databases
  -w /etc/group -p wa -k etcgroup
  -w /etc/passwd -p wa -k etcpasswd
  -w /etc/gshadow -k etcgroup
  -w /etc/shadow -k etcpasswd
  -w /etc/security/opasswd -k opasswd

  ## Sudoers file changes
  -w /etc/sudoers -p wa -k actions

  ## Passwd
  -w /usr/bin/passwd -p x -k passwd_modification

  ## Tools to change group identifiers
  -w /usr/sbin/groupadd -p x -k group_modification
  -w /usr/sbin/groupmod -p x -k group_modification
  -w /usr/sbin/addgroup -p x -k group_modification
  -w /usr/sbin/useradd -p x -k user_modification
  -w /usr/sbin/usermod -p x -k user_modification
  -w /usr/sbin/adduser -p x -k user_modification

  ## Login configuration and information
  -w /etc/login.defs -p wa -k login
  -w /etc/securetty -p wa -k login
  -w /var/log/faillog -p wa -k login
  -w /var/log/lastlog -p wa -k login
  -w /var/log/tallylog -p wa -k login

  ## Network Environment
  ### Changes to hostname
  -a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_modifications
  -a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modifications
  ### Changes to other files
  -w /etc/hosts -p wa -k network_modifications
  -w /etc/sysconfig/network -p wa -k network_modifications
  -w /etc/network/ -p wa -k network
  -a always,exit -F dir=/etc/NetworkManager/ -F perm=wa -k network_modifications
  ### Changes to issue
  -w /etc/issue -p wa -k etcissue
  -w /etc/issue.net -p wa -k etcissue

  ## System startup scripts
  -w /etc/inittab -p wa -k init
  -w /etc/init.d/ -p wa -k init
  -w /etc/init/ -p wa -k init

  ## Library search paths
  -w /etc/ld.so.conf -p wa -k libpath

  ## Pam configuration
  -w /etc/pam.d/ -p wa -k pam
  -w /etc/security/limits.conf -p wa  -k pam
  -w /etc/security/pam_env.conf -p wa -k pam
  -w /etc/security/namespace.conf -p wa -k pam
  -w /etc/security/namespace.init -p wa -k pam

  ## Postfix configuration
  -w /etc/aliases -p wa -k mail
  -w /etc/postfix/ -p wa -k mail

  ## SSH configuration
  -w /etc/ssh/sshd_config -k sshd

  # Systemd
  -w /bin/systemctl -p x -k systemd
  -w /etc/systemd/ -p wa -k systemd

  ## SELinux events that modify the system's Mandatory Access Controls (MAC)
  -w /etc/selinux/ -p wa -k mac_policy

  ## Critical elements access failures
  -a exit,always -F arch=b64 -S open -F dir=/etc -F success=0 -k unauthedfileaccess
  -a exit,always -F arch=b64 -S open -F dir=/bin -F success=0 -k unauthedfileaccess
  -a exit,always -F arch=b64 -S open -F dir=/sbin -F success=0 -k unauthedfileaccess
  -a exit,always -F arch=b64 -S open -F dir=/usr/bin -F success=0 -k unauthedfileaccess
  -a exit,always -F arch=b64 -S open -F dir=/usr/sbin -F success=0 -k unauthedfileaccess
  -a exit,always -F arch=b64 -S open -F dir=/var -F success=0 -k unauthedfileaccess
  -a exit,always -F arch=b64 -S open -F dir=/home -F success=0 -k unauthedfileaccess
  -a exit,always -F arch=b64 -S open -F dir=/srv -F success=0 -k unauthedfileaccess

  ## Process ID change (switching accounts) applications
  -w /bin/su -p x -k priv_esc
  -w /usr/bin/sudo -p x -k priv_esc
  -w /etc/sudoers -p rw -k priv_esc

  ## Power state
  -w /sbin/shutdown -p x -k power
  -w /sbin/poweroff -p x -k power
  -w /sbin/reboot -p x -k power
  -w /sbin/halt -p x -k power

  ## Session initiation information
  -w /var/run/utmp -p wa -k session
  -w /var/log/btmp -p wa -k session
  -w /var/log/wtmp -p wa -k session

  ## Discretionary Access Control (DAC) modifications
  -a always,exit -F arch=b32 -S chmod -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b32 -S chown -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b32 -S fchmod -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b32 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b32 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b32 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b32 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b32 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b32 -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b32 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b32 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b32 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b32 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b64 -S chmod  -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b64 -S chown -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b64 -S fchmod -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b64 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b64 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b64 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b64 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b64 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b64 -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b64 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b64 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b64 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
  -a always,exit -F arch=b64 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod

  # Special Rules ---------------------------------------------------------------

  ## 32bit API Exploitation
  ### If you are on a 64 bit platform, everything _should_ be running
  ### in 64 bit mode. This rule will detect any use of the 32 bit syscalls
  ### because this might be a sign of someone exploiting a hole in the 32
  ### bit API.
  -a always,exit -F arch=b32 -S all -k 32bit_api

  ## Reconnaissance
  -w /usr/bin/whoami -p x -k recon
  -w /etc/issue -p r -k recon
  -w /etc/hostname -p r -k recon

  ## Suspicious activity
  -w /usr/bin/wget -p x -k susp_activity
  -w /usr/bin/curl -p x -k susp_activity
  -w /usr/bin/base64 -p x -k susp_activity
  -w /bin/nc -p x -k susp_activity
  -w /bin/netcat -p x -k susp_activity
  -w /usr/bin/ncat -p x -k susp_activity
  -w /usr/bin/ssh -p x -k susp_activity
  -w /usr/bin/socat -p x -k susp_activity
  -w /usr/bin/wireshark -p x -k susp_activity
  -w /usr/bin/rawshark -p x -k susp_activity
  -w /usr/bin/rdesktop -p x -k sbin_susp

  ## Sbin suspicious activity
  -w /sbin/iptables -p x -k sbin_susp
  -w /sbin/ifconfig -p x -k sbin_susp
  -w /usr/sbin/tcpdump -p x -k sbin_susp
  -w /usr/sbin/traceroute -p x -k sbin_susp

  ## Injection
  ### These rules watch for code injection by the ptrace facility.
  ### This could indicate someone trying to do something bad or just debugging
  -a always,exit -F arch=b32 -S ptrace -k tracing
  -a always,exit -F arch=b64 -S ptrace -k tracing
  -a always,exit -F arch=b32 -S ptrace -F a0=0x4 -k code_injection
  -a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k code_injection
  -a always,exit -F arch=b32 -S ptrace -F a0=0x5 -k data_injection
  -a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k data_injection
  -a always,exit -F arch=b32 -S ptrace -F a0=0x6 -k register_injection
  -a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k register_injection

  ## Privilege Abuse
  ### The purpose of this rule is to detect when an admin may be abusing power by looking in user's home dir.
  -a always,exit -F dir=/home -F uid=0 -F auid>=1000 -F auid!=4294967295 -C auid!=obj_uid -k power_abuse

  # Software Management ---------------------------------------------------------

  # RPM (Redhat/CentOS)
  -w /usr/bin/rpm -p x -k software_mgmt
  -w /usr/bin/yum -p x -k software_mgmt

  # YAST/Zypper/RPM (SuSE)
  -w /sbin/yast -p x -k yast
  -w /sbin/yast2 -p x -k yast
  -w /bin/rpm -p x -k software_mgmt
  -w /usr/bin/zypper -k software_mgmt

  # DPKG / APT-GET (Debian/Ubuntu)
  -w /usr/bin/dpkg -p x -k software_mgmt
  -w /usr/bin/apt-add-repository -p x -k software_mgmt
  -w /usr/bin/apt-get -p x -k software_mgmt
  -w /usr/bin/aptitude -p x -k software_mgmt

  # Special Software ------------------------------------------------------------

  ## GDS specific secrets
  -w /etc/puppet/ssl -p wa -k puppet_ssl

  ## IBM Bigfix BESClient
  -a exit,always -F arch=b64 -S open -F dir=/opt/BESClient -F success=0 -k soft_besclient
  -w /var/opt/BESClient/ -p wa -k soft_besclient

  ## CHEF https://www.chef.io/chef/
  -w /etc/chef -p wa -k soft_chef

  # High volume events ----------------------------------------------------------

  ## Remove them if the cause to much volumen in your einvironment

  ## Root command executions
  -a exit,always -F arch=b64 -F euid=0 -S execve -k rootcmd
  -a exit,always -F arch=b32 -F euid=0 -S execve -k rootcmd

  ## File Deletion Events by User
  -a always,exit -F arch=b32 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
  -a always,exit -F arch=b64 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete

  ## File Access
  ### Unauthorized Access (unsuccessful)
  -a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k file_access
  -a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k file_access
  -a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k file_access
  -a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k file_access

  ### Unsuccessful Creation
  -a always,exit -F arch=b32 -S creat,link,mknod,mkdir,symlink,mknodat,linkat,symlinkat -F exit=-EACCES -k file_creation
  -a always,exit -F arch=b64 -S mkdir,creat,link,symlink,mknod,mknodat,linkat,symlinkat -F exit=-EACCES -k file_creation
  -a always,exit -F arch=b32 -S link,mkdir,symlink,mkdirat -F exit=-EPERM -k file_creation
  -a always,exit -F arch=b64 -S mkdir,link,symlink,mkdirat -F exit=-EPERM -k file_creation

  ### Unsuccessful Modification
  -a always,exit -F arch=b32 -S rename -S renameat -S truncate -S chmod -S setxattr -S lsetxattr -S removexattr -S lremovexattr -F exit=-EACCES -k file_modification
  -a always,exit -F arch=b64 -S rename -S renameat -S truncate -S chmod -S setxattr -S lsetxattr -S removexattr -S lremovexattr -F exit=-EACCES -k file_modification
  -a always,exit -F arch=b32 -S rename -S renameat -S truncate -S chmod -S setxattr -S lsetxattr -S removexattr -S lremovexattr -F exit=-EPERM -k file_modification
  -a always,exit -F arch=b64 -S rename -S renameat -S truncate -S chmod -S setxattr -S lsetxattr -S removexattr -S lremovexattr -F exit=-EPERM -k file_modification

  ### Record events for Docker
  -w /usr/bin/dockerd -k docker
  -w /usr/bin/docker -k docker
  -w /usr/bin/docker-containerd -k docker
  -w /usr/bin/docker-runc -k docker
  -w /var/lib/docker -k docker
  -w /etc/docker -k docker
  -w /etc/sysconfig/docker -k docker
  -w /etc/sysconfig/docker-storage -k docker
  -w /usr/lib/systemd/system/docker.service -k docker

  ### Record events for Kubelet daemon
  -w /usr/bin/kubelet -k kubelet

  # Make the configuration immutable --------------------------------------------
  ##-e 2
EOF
  service auditd restart

  DOCKERD_CIS_OPTIONS="--icc=false --log-level=info --iptables=true --live-restore --userland-proxy=false"
  sed -i s#ExecStart=/usr/bin/dockerd#ExecStart=/usr/bin/dockerd\ "$DOCKERD_CIS_OPTIONS"#g /usr/lib/systemd/system/docker.service
  systemctl daemon-reload
  systemctl restart docker.service

}

##################################### End Function Definitions
# Call checkos to ensure platform is Linux
checkos
# Verify dependencies are installed.
verify_dependencies
# Assuming it is, setup environment variables.
setup_environment_variables
# Read the options from cli input
TEMP=`getopt -o h:  --long help,banner:,enable:,tcp-forwarding:,x11-forwarding: -n $0 -- "$@"`
eval set -- "${TEMP}"
if [ $# == 1 ] ; then echo "No input provided! type ($0 --help) to see usage help" >&2 ; exit 1 ; fi
# extract options and their arguments into variables.
while true; do
    case "$1" in
        -h | --help)
            usage
            exit 1
            ;;
        --tcp-forwarding)
            TCP_FORWARDING="$2";
            shift 2
            ;;
        --x11-forwarding)
            X11_FORWARDING="$2";
            shift 2
            ;;
        --)
            break
            ;;
        *)
            break
            ;;
    esac
done

# BANNER CONFIGURATION
BANNER_FILE="/etc/ssh_banner"
SSH_BANNER_BASTION="LINUX BASTION"
SSH_BANNER_WORKERNODE="LINUX WORKERNODE"


# Enable/Disable TCP forwarding
TCP_FORWARDING=`echo "${TCP_FORWARDING}" | sed 's/\\n//g'`
# Enable/Disable X11 forwarding
X11_FORWARDING=`echo "${X11_FORWARDING}" | sed 's/\\n//g'`
echo "Value of TCP_FORWARDING - ${TCP_FORWARDING}"
echo "Value of X11_FORWARDING - ${X11_FORWARDING}"
if [[ ${TCP_FORWARDING} == "false" ]];then
    awk '!/AllowTcpForwarding/' /etc/ssh/sshd_config > temp && mv temp /etc/ssh/sshd_config
    echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
    harden_ssh_security
fi
if [[ ${X11_FORWARDING} == "false" ]];then
    awk '!/X11Forwarding/' /etc/ssh/sshd_config > temp && mv temp /etc/ssh/sshd_config
    echo "X11Forwarding no" >> /etc/ssh/sshd_config
fi
release=$(osrelease)
# AMZN Linux
amazon_os
prevent_process_snooping
# different banner and kubernetes hardening if workernode
if grep BastionLaunch /var/lib/cloud/instance/user-data.txt; then
  request_eip
  echo $SSH_BANNER_BASTION > $BANNER_FILE
  echo -e "\nBanner ${BANNER_FILE}" >>/etc/ssh/sshd_config
  service sshd restart
else
  echo $SSH_BANNER_WORKERNODE > $BANNER_FILE
  echo -e "\nBanner ${BANNER_FILE}" >>/etc/ssh/sshd_config
  systemctl restart sshd.service
  harden_workernode_kubernetes
fi
echo "Bootstrap complete."
