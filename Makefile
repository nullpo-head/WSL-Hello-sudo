RELEASE := release

.PHONY: all clean cleanall cleanrelease install release

all: build/pam_wsl_hello.so\
     build/WindowsHelloAuthenticator/WindowsHelloAuthenticator.exe\
     build/WindowsHelloKeyCredentialCreator/WindowsHelloKeyCredentialCreator.exe

build/pam_wsl_hello.so: | build
	cargo build --release
	strip target/release/libpam_wsl_hello.so
	cp ./target/release/libpam_wsl_hello.so build/pam_wsl_hello.so

build/WindowsHelloAuthenticator/WindowsHelloAuthenticator.exe build/WindowsHelloKeyCredentialCreator/WindowsHelloKeyCredentialCreator.exe: | build
	$(MAKE) -C win_components all
	cp -R win_components/build build/

build:
	mkdir -p build

clean:
	cargo clean

cleanall: clean
	$(MAKE) -C win_components clean

cleanrelease: cleanall
	rm -rf build
	rm -rf $(RELEASE)
	rm $(RELEASE).tar.gz

install: all
	./install.sh

release: all
	mkdir -p $(RELEASE)
	cp -R build $(RELEASE)/
	cp install.sh pam-config $(RELEASE)/
	tar cvzf $(RELEASE).tar.gz $(RELEASE)
