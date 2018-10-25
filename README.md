# cryptor-and-loader
A basic PE runtime cryptor, and accompanying loader. Currently implements a 6 byte XOR based encryption/decryption routine  

# how to  
`$ git clone https://github.com/quinn-samuel-perry/cryptor-and-loader.git`  
Open Visual Studio 2015 and build both projects  
Run the built `cryptor.exe`, which will encrypt the necessary code sections of the `loader.exe` program.  
The `loader.exe` will be what contains any malicious behaviour  
