# WSL Hello sudo

"WSL Hello sudo" is a Linux PAM module and companion Windows CLI apps that realize `sudo` by
biometric login of [Windows Hello](https://www.microsoft.com/en-us/windows/windows-hello) on Windows Subsystem for Linux (WSL).  
This PAM module allows you to authenticate `sudo` via face recognition, fingerprint authentication, and of couse machine-local PIN.
It runs in both WSL and WSL 2.

The Linux PAM module is written in Rust, and Windows CLI apps are written in C#.  
Please use it at your own risk. There is no warranty.

![demo](https://github.com/nullpo-head/WSL-Hello-sudo/blob/master/demo.gif)

"WSL Hello sudo" actually does __not__ modify your `sudo` command at all. It is a Linux PAM module.  
PAM, _Plaggable Authentication Module_, is a UNIX's module system that provides user authentication mechanisms to applications such as `sudo` or `su`. "WSL Hello sudo" is such a PAM module that lets applications use Windows Hello.

## Installation and Configuration

### Installation

The installation process is very simple.  
Please download the latest release package from GitHub Release and unpack it.  
Run `install.sh` inside the directory, and follow the instruction of `install.sh`

```ShellSession
$ wget http://github.com/nullpo-head/WSL-Hello-sudo/releases/latest/download/release.tar.gz
$ tar xvf release.tar.gz
$ cd release
$ ./install.sh
```

Although you don't have to care about the detailed installation process,  
`install.sh` does following things.

1. Copy small Windows CLI apps that launch Windows Hello to `C:\Users\your_account\pam_wsl_hello` (default location)  
2. Install a PAM module to your WSL system.
3. Create config files in `/etc/pam_wsl_hello/`
4. Create `uninstall.sh`

### Configuration

"WSL Hello sudo" is not a fork of `sudo` but a PAM module. So please configure `/etc/pam.d/sudo` to make it effective.  
I strongly recommend to set password of root first so that you can switch to it by `su`, in case you make some typo in the config of `sudo`.  
Add `auth sufficient pam_wsl_hello.so` to the top line of your `/etc/pam.d/sudo` like the following example  

```
#%PAM-1.0

auth       sufficient pam_wsl_hello.so
session    required   pam_env.so readenv=1 user_readenv=0
session    required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0
@include common-auth
@include common-account
@include common-session-noninteractive
```
Even if you fail to authenticate via Windows Hello, `sudo` moves on to the regular password authentication by this setting with `sufficient`.  

Other applications that authenticate users such as `su` can also utilize Windows Hello by this module.  
Even so, __I strongly recommend you to make either `sudo` or `su` free from this module to prevent from being locked out__

## Troubleshooting

### Windows Hello window appears in background.

The Windows Hello dialog sometimes appears in background.
In some cases, it even fails to recognize your face with some weird error message.
It seems a bug of Windows API. In that case, restarting Windows a couple of times might solve the problem.

### "Windows Hello is not invoked! `sudo` just prompts password!"

Maybe some error is happening. Unfortunately, `sudo` suppresses error messages from PAM modules.  
To debug "WSL Hello sudo", make it effective for `su` instead of `sudo`. `su` shows error messages from PAM modules,
so you can see what is going on.

For your information, the setting for `su` will be like the example below.
I will show only relevant two lines.
```
auth       sufficient pam_rootok.so
auth       sufficient pam_wsl_hello.so  
```

## Build

The Linux PAM module of "WSL Hello sudo" is written in Rust, and the Windows CLI apps are written in C#.  
So, `cargo` and Visual Studio are required to build it.

Before building "WSL Hello sudo", add the path to `MSBuild.exe` to `PATH` environment variable of __`bash` on WSL__, not Windows.  
If you build Windows CLI apps with your Visual Studio GUI, you can ignore that.
In my environment, MSBuild lives in `/mnt/c/Program Files (x86)/Microsoft Visual Studio/2019/Community/MSBuild/Current/Bin/`

To build "WSL Hello sudo", just run `make`.

```ShellSession
$ git clone https://github.com/nullpo-head/WSL-Hello-sudo.git
$ cd WSL-Hello-sudo
$ make
```
It invokes `cargo` and `MSBuild.exe` properly.

> Whether you're using `bash` or Windows, the repository must be in the Windows filesystem, otherwise `MSBuild.exe` won't work.

## Internals

Windows Hello maintains RSA key-pairs for each Windows user in its TPM hardware, and tells success of authentication by signing given contents by the private key.
To utilize its API, "WSL Hello sudo" contains small Windows CLI apps that return public key and singned signature of given content.
On the other hand, the PAM module of "WSL Hello sudo" remembers the public keys of each Windows user who corresponds to each Linux user.
So, the PAM module authenticates the given Linux user by the following process.

0. The PAM module is launched by `sudo` and receives a Linux user to be authenticated
1. The PAM module launches the companion Windows app and sends a random value via WSL's interop bridge
2. The companion Windows app invokes Windows Hello
3. Windows Hello makes a signature of the given input by the private key of the current Windows user
4. The companion Windows app returns the signature
5. The PAM module verifies the signature by the public key of the Windows user who corresponds to the given Linux user.

