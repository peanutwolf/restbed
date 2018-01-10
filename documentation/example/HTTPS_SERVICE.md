Overview
--------

"HTTPS (HTTP Secure) is an extension of the Hypertext Transfer Protocol (HTTP) for secure communication over a computer network, and is widely used on the Internet. In HTTPS, the communication protocol is encrypted by Transport Layer Security (TLS), or formerly, its predecessor, Secure Sockets Layer (SSL). The protocol is therefore also often referred to as HTTP over TLS, or HTTP over SSL." -- [Wikipedia](https://en.wikipedia.org/wiki/HTTPS)

Example
-------

```C++
#include <memory>
#include <cstdlib>
#include <restbed>
#include <openssl\bio.h>
#include <openssl\pkcs12.h>
#include <openssl\pem.h>
#include <openssl\err.h>
#include <asio\buffer.hpp>
#include <Windows.h>
#include <Winreg.h>
#include <fstream>
#include <iostream>
#include <thread>
#include <chrono>

#include "rapidjson\document.h"     
#include "rapidjson\prettywriter.h" 
#include "rapidjson\istreamwrapper.h"

#include "custom_logger.hpp"

using namespace rapidjson;
using namespace std;
using namespace restbed; 

static inline const char pseparator() {
#if defined(WIN32) || defined(_WIN32)
	return '\\';
#else
	return '/';
#endif
}

string path_append(const string &path) {
	string path_tmp = path;
	if (path_tmp.length() > 0) {
		path_tmp.insert(path_tmp.begin(), pseparator());
	}
	return path_tmp;
}

void get_method_handler( const shared_ptr< Session > session )
{
	const auto request = session->get_request();

	size_t content_length = request->get_header("Content-Length", 0);

	session->fetch(content_length, [request](const shared_ptr< Session > session, const Bytes & body)
	{
		fprintf(stdout, "%.*s\n", (int)body.size(), body.data());
		session->close(OK, "Hello, World!", { { "Content-Length", "13" },{ "Connection", "close" } });
	});
}

class SecureRedirectRule : public Rule {
public:
	SecureRedirectRule(const uint16_t http_port, const uint16_t secure_port) :
		Rule(), _http_port(http_port), _secure_port(secure_port) {}

	virtual void action(const std::shared_ptr< Session > session, const std::function< void(const std::shared_ptr< Session >) >& callback) {
		auto destination = session->get_destination();
		uint16_t port = parse_port(destination);

		if (port == _http_port) {
			auto redirect_url = string("https://");
			auto path  = session->get_request()->get_path();
			//auto query = session->get_request()->get_query_parameters();

			redirect_url += parse_ip(destination)+ ":" + to_string(_secure_port);

			if (not path.empty()) {
				redirect_url += path;
			}
			//TODO add query params
			/*if (not query.empty()) {
				redirect_url += query;
			}*/
			session->close(FOUND,
				{ { "Content-Length", "0" },{ "Location", redirect_url.c_str() } });
			
		}else{
			callback(session);
		}
	}

private:
	uint16_t parse_port(const string &ip_addr) {
		int pos = ip_addr.find_last_of(':');
		if (pos == string::npos)
			return 0;
		auto port_str = ip_addr.substr(pos+1);
		return stoi(port_str);
	}

	string parse_ip(const string &ip_addr) {
		int pos = ip_addr.find_last_of(':');
		if (pos == string::npos)
			return "[::]";
		return ip_addr.substr(0, pos);
	}

	uint16_t _http_port;
	uint16_t _secure_port;
};



LONG GetStringRegKey(HKEY hKey, const std::wstring &strValueName, std::wstring &strValue, const std::wstring &strDefaultValue)
{
	strValue = strDefaultValue;
	WCHAR szBuffer[512];
	DWORD dwBufferSize = sizeof(szBuffer);
	ULONG nError;
	nError = RegQueryValueExW(hKey, strValueName.c_str(), 0, NULL, (LPBYTE)szBuffer, &dwBufferSize);
	if (ERROR_SUCCESS == nError)
	{
		strValue = szBuffer;
	}
	return nError;
}

int getLogonTouchRegParam(const string &param, string &path) {
	HKEY hKey;
	LONG lRes = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\LogonTouch", 0, KEY_READ, &hKey);
	if (lRes != ERROR_SUCCESS) return -1;

	std::wstring str_tmp;
	std::wstring param_tmp(param.begin(), param.end());
	GetStringRegKey(hKey, param_tmp, str_tmp, L"");
	path.assign(str_tmp.begin(), str_tmp.end());

	RegCloseKey(hKey);

	return 0;
}

struct ServerKeysDirImpl { 
	string path = "";
	string publicstore = "publicstore.pkcs12";
	string publicpass = "publicstore.key";
	string privatestore = "privatestore.pkcs12";
	string privatepass = "publicstore.key";
};

struct ClientKeysDirImpl {
	string path = "";
	string publicstore = "publicstore.pkcs12";
	string publicpass = "publicstore.key";
	string credentials = "credentials.cip";
};

struct KeysDirImpl {
	string path = "";
	ServerKeysDirImpl m_server_dir;
	ClientKeysDirImpl m_client_dir;
};

struct ServerConfigImpl {
	string version = "0.0";
	uint16_t http_port = 8080;
	uint16_t https_port = 7779;
	KeysDirImpl m_keys_dir;
};

class ServerConfig {
public:
	ServerConfig(const string &install_path, shared_ptr<ServerConfigImpl> impl) : install_path(install_path), m_pimpl(impl) {}

	uint16_t getHTTPPort() {
		return m_pimpl->http_port;
	}
	
	uint16_t getHTTPSPort() {
		return m_pimpl->https_port;
	}

	const string getServerPrivateStorePath() {
		return install_path 
			+ path_append(m_pimpl->m_keys_dir.path)
			+ path_append(m_pimpl->m_keys_dir.m_server_dir.path)
			+ path_append(m_pimpl->m_keys_dir.m_server_dir.privatestore);
	}

	const string getServerPrivatePassPath() {
		return install_path
			+ path_append(m_pimpl->m_keys_dir.path)
			+ path_append(m_pimpl->m_keys_dir.m_server_dir.path)
			+ path_append(m_pimpl->m_keys_dir.m_server_dir.privatepass);
	}

	const string getClientPublicStorePath() {
		return install_path
			+ path_append(m_pimpl->m_keys_dir.path)
			+ path_append(m_pimpl->m_keys_dir.m_client_dir.path)
			+ path_append(m_pimpl->m_keys_dir.m_client_dir.publicstore);
	}

	const string getClientPublicPassPath() {
		return install_path
			+ path_append(m_pimpl->m_keys_dir.path)
			+ path_append(m_pimpl->m_keys_dir.m_client_dir.path)
			+ path_append(m_pimpl->m_keys_dir.m_client_dir.publicpass);
	}

	const string getServerPrivatePass() {
		string pass_tmp;
		ifstream passfile_stream(getServerPrivatePassPath());
		getline(passfile_stream, pass_tmp);

		return pass_tmp;
	}

	const string getClientPublicPass() {
		string pass_tmp;
		ifstream passfile_stream(getClientPublicPassPath());
		getline(passfile_stream, pass_tmp);

		return pass_tmp;
	}
private:
	shared_ptr<ServerConfigImpl> m_pimpl = make_shared<ServerConfigImpl>();
	string install_path = "";
};

class LogonTouchConfigParser {
public:
	LogonTouchConfigParser(const string &path) : _config_path(path) {}

	shared_ptr<ServerConfigImpl> parseServerConfig() {
		ifstream ifs(_config_path);
		IStreamWrapper isw(ifs);

		_document.ParseStream(isw);
		if (_document.HasParseError()) {
			return nullptr;
		}
		auto serverConfig = make_shared<ServerConfigImpl>();
		if (!_document.HasMember("ServerConfig")) return nullptr;

		Value srvCfg = _document["ServerConfig"].GetObject();

		fillServerConfig(srvCfg, serverConfig);

		return serverConfig;
	}
private:
	void fillServerConfig(Value &srvCfg, shared_ptr<ServerConfigImpl> &config) {
		if (srvCfg.HasMember("version") && srvCfg["version"].IsString())
			config->version = srvCfg["version"].GetString();

		if (srvCfg.HasMember("HTTPPort") && srvCfg["HTTPPort"].IsUint())
			config->http_port = srvCfg["HTTPPort"].GetUint();

		if (srvCfg.HasMember("HTTPSPort") && srvCfg["HTTPSPort"].IsUint())
			config->https_port = srvCfg["HTTPSPort"].GetUint();

		if (srvCfg.HasMember("KeysDir") && srvCfg["KeysDir"].IsObject()) {
			Value keysDir = srvCfg["KeysDir"].GetObject();
			fillKeysDirConfig(keysDir, &config->m_keys_dir);
		}

	}

	void fillKeysDirConfig(Value &keysDir, KeysDirImpl *config) {
		if (keysDir.HasMember("path") && keysDir["path"].IsString())
			config->path = keysDir["path"].GetString();

		if (keysDir.HasMember("ServerKeysDir") && keysDir["ServerKeysDir"].IsObject()) {
			Value srvKeysDir = keysDir["ServerKeysDir"].GetObject();
			fillServerKeysDir(srvKeysDir, &config->m_server_dir);
		}

		if (keysDir.HasMember("ClientKeysDir") && keysDir["ClientKeysDir"].IsObject()) {
			Value clntKeysDir = keysDir["ClientKeysDir"].GetObject();
			fillClientKeysDir(clntKeysDir, &config->m_client_dir);
		}
	}

	void fillServerKeysDir(Value &srvKeysDir,ServerKeysDirImpl *config) {
		if (srvKeysDir.HasMember("path") && srvKeysDir["path"].IsString())
			config->path = srvKeysDir["path"].GetString();

		if (srvKeysDir.HasMember("PrivateStore") && srvKeysDir["PrivateStore"].IsString())
			config->privatestore = srvKeysDir["PrivateStore"].GetString();

		if (srvKeysDir.HasMember("PrivatePass") && srvKeysDir["PrivatePass"].IsString())
			config->privatepass = srvKeysDir["PrivatePass"].GetString();

		if (srvKeysDir.HasMember("PublicStore") && srvKeysDir["PublicStore"].IsString())
			config->publicstore = srvKeysDir["PublicStore"].GetString();

		if (srvKeysDir.HasMember("PublicPass") && srvKeysDir["PublicPass"].IsString())
			config->publicpass = srvKeysDir["PublicPass"].GetString();
	}

	void fillClientKeysDir(Value &clntKeysDir, ClientKeysDirImpl *config) {
		if (clntKeysDir.HasMember("path") && clntKeysDir["path"].IsString())
			config->path = clntKeysDir["path"].GetString();

		if (clntKeysDir.HasMember("PublicStore") && clntKeysDir["PublicStore"].IsString())
			config->publicstore = clntKeysDir["PublicStore"].GetString();

		if (clntKeysDir.HasMember("PublicPass") && clntKeysDir["PublicPass"].IsString())
			config->publicpass = clntKeysDir["PublicPass"].GetString();

		if (clntKeysDir.HasMember("Credentials") && clntKeysDir["Credentials"].IsString())
			config->credentials = clntKeysDir["Credentials"].GetString();
	}

	string   _config_path = "";
	Document _document;
}; 


class LongonTouchServer {
public:

	LongonTouchServer(shared_ptr<ServerConfig> config) : m_config(config) {}

	int Set_Server_Keys_P12(const string &p12_path, const string &p12_pass) {
		auto p12_holder = Load_Keys_P12(p12_path, p12_pass);

		if (p12_holder->pkey) {
			unsigned char *pkey_buf = NULL;
			int key_size = i2d_PrivateKey(p12_holder->pkey, &pkey_buf);
			m_ssl_settings.set_private_key(pkey_buf, key_size);
		}

		if (p12_holder->cert) {
			unsigned char *cert_buf = NULL;
			int cert_size = i2d_X509(p12_holder->cert, &cert_buf);
			m_ssl_settings.set_certificate(cert_buf, cert_size);
		}

		return 1;
	}

	int Set_Auth_Keys_P12(const string &p12_path, const string &p12_pass) {
		auto p12_holder = Load_Keys_P12(p12_path, p12_pass);
		auto bio_mem = shared_ptr<BIO>(BIO_new(BIO_s_mem()), BIO_free);

		if (!PEM_write_bio_X509(bio_mem.get(), sk_X509_pop(p12_holder->ca))) {
			return -1;
		}

		unsigned char *ca_cert_buf = NULL;
		int ca_cert_size = BIO_get_mem_data(bio_mem.get(), &ca_cert_buf);

		m_ssl_settings.set_client_authentication_enabled(true);
		m_ssl_settings.set_ca_certificate(ca_cert_buf, ca_cert_size);

		return 1;
	}

	void Server_Assemble(const function< void(const shared_ptr< Session > session) >& callback) {
		auto resource = make_shared< Resource >();
		resource->set_path("/resource");
		resource->add_rule(make_shared<SecureRedirectRule>(m_config->getHTTPPort(), m_config->getHTTPSPort()));
		resource->set_method_handler("GET", callback);
		
		Set_Server_Keys_P12(m_config->getServerPrivateStorePath(), m_config->getServerPrivatePass());
		Set_Auth_Keys_P12(m_config->getClientPublicStorePath(), m_config->getClientPublicPass());

		m_ssl_settings.set_http_disabled(false);
		m_ssl_settings.set_port(m_config->getHTTPSPort());
		m_ssl_settings.set_temporary_diffie_hellman(Uri("file://dh2048.pem"));

		m_settings.set_port(m_config->getHTTPPort());
		m_settings.set_ssl_settings(shared_ptr<SSLSettings>(&m_ssl_settings));

		m_service.publish(resource);
		m_service.set_logger(make_shared< CustomLogger >());
	}

	void Server_Start() {
		m_service.start(shared_ptr<Settings>(&m_settings));
	}

	void Server_Stop() {
		m_service.stop();
	}

private:

	typedef struct p12_holder {
		~p12_holder() {
			if (pkey != NULL) EVP_PKEY_free(pkey);
			if (cert != NULL) X509_free(cert);
			if (ca != NULL)   sk_X509_pop_free(ca, X509_free);
		}

		EVP_PKEY *pkey = NULL;
		X509 *cert = NULL;
		STACK_OF(X509) *ca = NULL;
	}p12_holder_t;


	shared_ptr<p12_holder_t> Load_Keys_P12(const string &p12_path, const string &p12_pass) {
		auto holder = make_shared<p12_holder_t>();

		EVP_PKEY *pkey = NULL;
		X509 *cert = NULL;
		STACK_OF(X509) *ca = NULL;

		auto p12_bio = shared_ptr<BIO>(BIO_new_file(p12_path.c_str(), "r"), BIO_free);
		if (p12_bio == nullptr) nullptr;

		auto p12_cert = shared_ptr<PKCS12>(d2i_PKCS12_bio(p12_bio.get(), NULL), PKCS12_free);
		if (p12_cert == nullptr) nullptr;

		int res = PKCS12_parse(p12_cert.get(), p12_pass.c_str(), &holder->pkey, &holder->cert, &holder->ca);

		return holder;
	}

	Settings      m_settings;
	SSLSettings   m_ssl_settings;
	Service       m_service;

	const shared_ptr<ServerConfig> m_config = nullptr;
};

void server_thread(LongonTouchServer *server) {
	server->Server_Start();
}

int main( const int, const char** )
{
	string path;
	string install_path;
	
	getLogonTouchRegParam("Config", path);
	getLogonTouchRegParam("", install_path);

	LogonTouchConfigParser configParser(path);

	auto serverCfg = configParser.parseServerConfig();

	auto serverConfig = make_shared<ServerConfig>(install_path, serverCfg);


	auto srv = make_shared<LongonTouchServer>(serverConfig);

	srv->Server_Assemble([=] (const shared_ptr< Session > session){
		srv->Server_Stop();
	});

	//srv.Server_Start();

	thread srv_thread(server_thread, srv.get());
	srv_thread.join();
    return EXIT_SUCCESS;
}
```

Build
-----

> $ clang++ -o example example.cpp -l restbed -l ssl -l crypt

Execution
---------

> $ cd /tmp
>
> $ openssl genrsa -out server.key 1024
>
> $ openssl req -new -key server.key -out server.csr
>
> $ openssl x509 -req -days 3650 -in server.csr -signkey server.key -out server.crt
>
> $ openssl dhparam -out dh768.pem 768
> 
> $ sudo ./example
>
> $ curl -k -v -w'\n' -X GET 'https://localhost/resource'
