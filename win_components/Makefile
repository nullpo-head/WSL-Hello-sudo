.PHONY: all clean

all: build/WindowsHelloAuthenticator/WindowsHelloAuthenticator.exe \
     build/WindowsHelloKeyCredentialCreator/WindowsHelloKeyCredentialCreator.exe

%.exe: app=$(patsubst %.exe,%,$(@F))

build/%.exe: build FORCE
	@if ! command -v MSBuild.exe > /dev/null; then \
	  echo "MSBuild.exe is not found in \$$PATH. Set the path to Visual Studio's MSBuild"; \
	  exit 1; \
	fi
	MSBuild.exe $(app) /t:Restore,Build /p:Configuration=Release
	mkdir -p "build/${app}"
	cp "${app}/${app}/bin/Release/${app}.exe" "build/${app}/"

FORCE: ;

build:
	mkdir -p build

clean:
	rm -rf build
	MSBuild.exe WindowsHelloAuthenticator /t:Clean /p:Configuration=Release
	MSBuild.exe WindowsHelloKeyCredentialCreator /t:Clean /p:Configuration=Release
