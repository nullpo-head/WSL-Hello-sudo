RELEASE := release

WIN_CARGO="cargo.exe"

.PHONY: all clean cleanall cleanrelease install release

all: build/pam_wsl_hello.so build/WindowsHelloBridge.exe

build/pam_wsl_hello.so: | build
# Build the PAM lib from Linux
	cargo build --release -p wsl_hello_pam
	strip target/release/libpam_wsl_hello.so
	cp ./target/release/libpam_wsl_hello.so build/pam_wsl_hello.so

build/WindowsHelloBridge.exe: | build
# Build the authenticator from Windows
	$(WIN_CARGO) build -p win_hello_bridge --release
	strip target/release/WindowsHelloBridge.exe
	cp ./target/release/WindowsHelloBridge.exe ./build

build:
	mkdir -p build

clean:
	cargo clean

cleanall: clean

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
