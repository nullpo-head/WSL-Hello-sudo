#!/bin/bash

set -e

prompt_yn () {
  read -r -p "$1: " response
  if [[ -z "$response" ]]; then
    response="$2"
  fi
  if [[ "$response" =~ ^([yY][eE][sS]|[yY])+$ ]]; then
    true
  elif [[ "$response" =~ ^([nN][oO]|[nN])+$ ]]; then
    false
  else
    $(prompt_yn "$1" "$2")
  fi
}

echo_stage () {
  echo -e "\e[32m$*\e[m"
}

check_pam_directory () {
  if [[ -e "$1" && "$(find "$1" -maxdepth 1 -name 'pam_*.so')" ]]; then
    true
  else
    false
  fi
}


if [ `whoami` = "root" ]; then
  echo "Please run this with normal user instead of root. Aborting"
  exit 1
fi
if [ ! -e build/pam_wsl_hello.so ] || \
  [ ! -e build/WindowsHelloAuthenticator/WindowsHelloAuthenticator.exe ] || \
  [ ! -e build/WindowsHelloKeyCredentialCreator/WindowsHelloKeyCredentialCreator.exe ]; then
    echo "No built binary is found. Buld first before installing"
    exit 1
fi

MNT=/mnt/c
if [[ ! -e "${MNT}" ]]; then
  echo "'/mnt/c' is not found. Please input your mount point of C drive to invoke Windows commands."
  echo -n ": "
  read MNT
fi
WINUSER=`${MNT}/Windows/System32/cmd.exe /C "echo | set /p dummy=%username%"` # Hacky. Get Windows's user name without new line
DEF_PAM_WSL_HELLO_WINPATH="${MNT}/Users/$WINUSER/pam_wsl_hello"
echo "Input the install location for Windows Hello authentication components."
echo "They are Windows .exe files and required to be in a valid Windows directory"
echo -n "Default [${DEF_PAM_WSL_HELLO_WINPATH}] :" 
read PAM_WSL_HELLO_WINPATH
if [ -z "$PAM_WSL_HELLO_WINPATH" ]; then
  PAM_WSL_HELLO_WINPATH=$DEF_PAM_WSL_HELLO_WINPATH
fi
if [ ! -e $PAM_WSL_HELLO_WINPATH ]; then
  if prompt_yn "'$PAM_WSL_HELLO_WINPATH' does not exist. Create it? [Y/n]" "y"; then
    set -x
    mkdir -p $PAM_WSL_HELLO_WINPATH
  fi
fi
set +x
echo_stage "[1/5] Installing Windows components of WSL-Hello-sudo..."
set -x
cp -r build/{WindowsHelloAuthenticator,WindowsHelloKeyCredentialCreator} "$PAM_WSL_HELLO_WINPATH/"

set +x
echo_stage "[2/5] Installing PAM module to the Linux system..."
SECURITY_PATH="/lib/x86_64-linux-gnu/security" 
if ! check_pam_directory "${SECURITY_PATH}"; then
  echo "PAM directory is not found in '/lib/x86_64-linux-gnu/security/'. It looks you're not running Ubuntu nor Debian."
  echo "Checking '/lib/security/'..."
  SECURITY_PATH="/lib/security" 
  while ! check_pam_directory "${SECURITY_PATH}"; do
    echo "PAM module directory is not found in '${SECURITY_PATH}'."
    echo "Please input the path of the PAM module's directory."
    echo -n ": "
    read SECURITY_PATH
  done
fi
echo "Confirmed the '${SECURITY_PATH}' is the PAM module directory."
PAM_SO="${SECURITY_PATH}/pam_wsl_hello.so"
if [ -e "${PAM_SO}" ]; then
  if prompt_yn "'${PAM_SO}' is in use. Do you proceed to remove the current? [Y/n]" "y"; then 
    set -x
    sudo rm "${PAM_SO}"
    set +x
  else
    echo "Installation is cancelled. You can rerun this install.sh after that."
    exit
  fi
fi
set -x
sudo cp build/pam_wsl_hello.so "${SECURITY_PATH}/"
sudo chown root:root "${SECURITY_PATH}/pam_wsl_hello.so"
sudo chmod 644 "${SECURITY_PATH}/pam_wsl_hello.so"

set +x
echo_stage "[3/5] Createing the config files of WSL-Hello-sudo..."
set -x
sudo mkdir -p /etc/pam_wsl_hello/
set +x
if [ ! -e "/etc/pam_wsl_hello/config" ] || prompt_yn "'/etc/pam_wsl_hello/config' already exists. Overwrite it? [y/N]" "n" ; then
  set -x
  sudo touch /etc/pam_wsl_hello/config
  sudo echo "authenticator_path = \"$PAM_WSL_HELLO_WINPATH/WindowsHelloAuthenticator/WindowsHelloAuthenticator.exe\"" | sudo tee /etc/pam_wsl_hello/config
else
  echo "skip creation of '/etc/pam_wsl_hello/config'"
fi
echo "Please authenticate yourself now to create a credential for '$USER' and '$WINUSER' pair."
KEY_ALREADY_EXIST_ERR=170
set -x
pushd $PAM_WSL_HELLO_WINPATH
WindowsHelloKeyCredentialCreator/WindowsHelloKeyCredentialCreator.exe pam_wsl_hello_$USER|| test $? = $KEY_ALREADY_EXIST_ERR
sudo mkdir -p /etc/pam_wsl_hello/public_keys
popd
sudo cp "$PAM_WSL_HELLO_WINPATH"/pam_wsl_hello_$USER.pem /etc/pam_wsl_hello/public_keys/

set +x
echo_stage "[4/5] Createing uninstall.sh..."
if [ ! -e "uninstall.sh" ] || prompt_yn "'uninstall.sh' already exists. Overwrite it? [Y/n]" "y" ; then
  cat > uninstall.sh << EOS
  echo -e "\e[31mNote: Please ensure that config files in /etc/pam.d/ are restored to as they were before WSL-Hello-sudo was installed\e[m"
  set -x
  sudo rm -rf /etc/pam_wsl_hello
  sudo rm "${SECURITY_PATH}/pam_wsl_hello.so"
  rm -rf ${PAM_WSL_HELLO_WINPATH}
EOS
  chmod +x uninstall.sh
else
  echo "skip creation of 'uninstall.sh'"
fi
set -x
set +x
echo_stage "[5/5] Done!"
echo "Installation is done! Configure your /etc/pam.d/sudo to make WSL-Hello-sudo effective."
echo "If you want to uninstall WSL-Hello-sudo, run uninstall.sh"
