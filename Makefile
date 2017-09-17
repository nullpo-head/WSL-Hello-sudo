
.PHONY: all clean install

all: build/pam_wsl_hello.so\
     build/WindowsHelloAuthenticator/WindowsHelloAuthenticator.exe\
     build/WindowsHelloKeyCredentialCreator/WindowsHelloKeyCredentialCreator.exe

build/pam_wsl_hello.so: build FORCE
	cargo build --release
	cp ./target/release/libpam_wsl_hello.so build/pam_wsl_hello.so

build/WindowsHelloAuthenticator/WindowsHelloAuthenticator.exe: build FORCE
	@if ! command -v MSBuild.exe > /dev/null; then \
	  echo "MSBuild.exe is not found in \$$PATH. Set the path to Visual Studio's MSBuild"; \
	  exit 1; \
	fi
	cd ./win_components/WindowsHelloAuthenticator;\
	MSBuild.exe "/t:Build" "/p:Configuration=Release"
	mkdir -p build/WindowsHelloAuthenticator
	cp ./win_components/WindowsHelloAuthenticator/WindowsHelloAuthenticator/bin/Release/* build/WindowsHelloAuthenticator/

build/WindowsHelloKeyCredentialCreator/WindowsHelloKeyCredentialCreator.exe: build FORCE
	@if ! command -v MSBuild.exe > /dev/null; then \
	  echo "MSBuild.exe is not found in \$$PATH. Set the path to Visual Studio's MSBuild"; \
	  exit 1; \
	fi
	cd ./win_components/WindowsHelloKeyCredentialCreator;\
	MSBuild.exe "/t:Build" "/p:Configuration=Release"
	mkdir -p build/WindowsHelloKeyCredentialCreator
	cp ./win_components/WindowsHelloKeyCredentialCreator/WindowsHelloKeyCredentialCreator/bin/Release/* build/WindowsHelloKeyCredentialCreator/

FORCE:  ;
build:
	mkdir -p build

clean:
	cargo clean
	cd ./win_components/WindowsHelloKeyCredentialCreator;\
	MSBuild.exe "/t:Clean" "/p:Configuration=Release"
	cd ./win_components/WindowsHelloAuthenticator;\
	MSBuild.exe "/t:Clean" "/p:Configuration=Release"
	rm -rf build
	rm -rf release
	rm release.tar.gz

install: all
	./install.sh

release: all
	mkdir -p release
	cp -R build release/
	cp install.sh release/
	tar cvzf release.tar.gz release
