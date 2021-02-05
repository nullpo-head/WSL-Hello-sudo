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

STEPS=6
CURRENT_STEP=0
echo_stage () {
  let CURRENT_STEP=CURRENT_STEP+1
  echo -e "\e[32m[$CURRENT_STEP/$STEPS] $*\e[m"
}

check_pam_directory () {
  if [[ -e "$1" && "$(find "$1" -maxdepth 1 -name 'pam_*.so')" ]]; then
    true
  else
    false
  fi
}


if [ `whoami` = "root" ]; then
  echo "Please run this as normal user instead of root. Aborting."
  exit 1
fi
if [ ! -e build/pam_wsl_hello.so ] || \
  [ ! -e build/WindowsHelloAuthenticator/WindowsHelloAuthenticator.exe ] || \
  [ ! -e build/WindowsHelloKeyCredentialCreator/WindowsHelloKeyCredentialCreator.exe ]; then
    echo "No built binary was found. Build first before installing."
    exit 1
fi

MNT=/mnt/c
if [[ ! -e "${MNT}" ]]; then
  echo "'/mnt/c' was not found. Please input the mount point of your C drive to invoke Windows commands."
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
if [ ! -e "$PAM_WSL_HELLO_WINPATH" ]; then
  if prompt_yn "'$PAM_WSL_HELLO_WINPATH' does not exist. Create it? [Y/n]" "y"; then
    set -x
    mkdir -p "$PAM_WSL_HELLO_WINPATH"
  fi
fi
set +x
echo_stage "Installing Windows components of WSL-Hello-sudo..."
set -x
cp -r build/{WindowsHelloAuthenticator,WindowsHelloKeyCredentialCreator} "$PAM_WSL_HELLO_WINPATH/"

set +x
echo_stage "Installing PAM module to the Linux system..."
SECURITY_PATH="/lib/x86_64-linux-gnu/security" 
if ! check_pam_directory "${SECURITY_PATH}"; then
  echo "PAM directory was not found in '/lib/x86_64-linux-gnu/security/'. It looks like you're not running Ubuntu nor Debian."
  echo "Checking '/lib/security/'..."
  SECURITY_PATH="/lib/security" 
  while ! check_pam_directory "${SECURITY_PATH}"; do
    echo "PAM module directory was not found in '${SECURITY_PATH}'."
    echo "Please input the path of the PAM module's directory."
    echo -n ": "
    read SECURITY_PATH
  done
fi
echo "Confirmed '${SECURITY_PATH}' as the PAM module directory."
PAM_SO="${SECURITY_PATH}/pam_wsl_hello.so"
if [ -e "${PAM_SO}" ]; then
  if prompt_yn "'${PAM_SO}' is in use. Proceed to remove the current one? [Y/n]" "y"; then 
    set -x
    sudo rm "${PAM_SO}"
    set +x
  else
    echo "Installation was cancelled. You can rerun this with install.sh later."
    exit
  fi
fi
set -x
sudo cp build/pam_wsl_hello.so "${SECURITY_PATH}/"
sudo chown root:root "${SECURITY_PATH}/pam_wsl_hello.so"
sudo chmod 644 "${SECURITY_PATH}/pam_wsl_hello.so"

set +x
echo_stage "Creating pam-config..."
PAM_CONFIG_INSTALLED=no
PAM_CONFIGS_PATH=/usr/share/pam-configs
PAM_CONFIG_NAME=wsl-hello
if [ -d "${PAM_CONFIGS_PATH}" ]; then
  PAM_CONFIG=${PAM_CONFIGS_PATH}/${PAM_CONFIG_NAME}
  if [ ! -e "${PAM_CONFIG}" ] || prompt_yn "'${PAM_CONFIG}' already exists. Overwrite it? [Y/n]" "y"; then
    set -x
    sudo cp pam-config "${PAM_CONFIG}"
    set +x
    PAM_CONFIG_INSTALLED=yes
  else
    echo "Skipping creation of '${PAM_CONFIG}'..."
  fi
else
  echo "PAM config directory was not found in '${PAM_CONFIGS_PATH}'. It looks like you're not running Ubuntu nor Debian. You will have to configure pam manually."
fi

echo_stage "Creating the config files of WSL-Hello-sudo..."
set -x
sudo mkdir -p /etc/pam_wsl_hello/
set +x
if [ ! -e "/etc/pam_wsl_hello/config" ] || prompt_yn "'/etc/pam_wsl_hello/config' already exists. Overwrite it? [y/N]" "n" ; then
  set -x
  sudo touch /etc/pam_wsl_hello/config
  sudo echo "authenticator_path = \"$PAM_WSL_HELLO_WINPATH/WindowsHelloAuthenticator/WindowsHelloAuthenticator.exe\"" | sudo tee /etc/pam_wsl_hello/config
else
  echo "Skipping creation of '/etc/pam_wsl_hello/config'..."
fi
echo "Please authenticate yourself now to create a credential for '$USER' and '$WINUSER' pair."
KEY_ALREADY_EXIST_ERR=170
set -x
pushd "$PAM_WSL_HELLO_WINPATH"
WindowsHelloKeyCredentialCreator/WindowsHelloKeyCredentialCreator.exe pam_wsl_hello_$USER|| test $? = $KEY_ALREADY_EXIST_ERR
sudo mkdir -p /etc/pam_wsl_hello/public_keys
popd
sudo cp "$PAM_WSL_HELLO_WINPATH"/pam_wsl_hello_$USER.pem /etc/pam_wsl_hello/public_keys/

set +x
echo_stage "Creating uninstall.sh..."
if [ ! -e "uninstall.sh" ] || prompt_yn "'uninstall.sh' already exists. Overwrite it? [Y/n]" "y" ; then
  cat > uninstall.sh << EOS
  echo -e "\e[31mNote: Please ensure that config files in /etc/pam.d/ are restored to as they were before WSL-Hello-sudo was installed\e[m"
  set -x
  sudo rm -rf /etc/pam_wsl_hello
  sudo rm "${SECURITY_PATH}/pam_wsl_hello.so"
  if [ -e "${PAM_CONFIG}" ]; then
    sudo pam-auth-update --remove "${PAM_CONFIG_NAME}"
    sudo rm "${PAM_CONFIG}"
  fi
  rm -rf ${PAM_WSL_HELLO_WINPATH}
EOS
  chmod +x uninstall.sh
else
  echo "Skipping creation of 'uninstall.sh'..."
fi
set -x
set +x
echo_stage "Done!"
echo -n "Installation is done! "
if [ "$PAM_CONFIG_INSTALLED" = "yes" ]; then
  if prompt_yn "Do you want to enable the pam module now? [y/N]" "n"; then
    set -x
    sudo pam-auth-update --enable "${PAM_CONFIG_NAME}"
    set +x
  fi
  echo "You can call 'sudo pam-auth-update' to enable/disable WSL Hello authentication."
else
  echo "Configure your /etc/pam.d/sudo to make WSL-Hello-sudo effective."
fi
echo "If you want to uninstall WSL-Hello-sudo, run uninstall.sh"
