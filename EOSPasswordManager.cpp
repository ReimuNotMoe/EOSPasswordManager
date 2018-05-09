/*
    This file is part of EOSPasswordManager.
    Copyright (C) 2018  ReimuNotMoe <reimuhatesfdt@gmail.com>
    EOSPasswordManager is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    EOSPasswordManager is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with EOSPasswordManager.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <eosiolib/eosio.hpp>
#include <eosiolib/print.hpp>
#include <string>
#include <iostream>
#include <vector>

#include <endian.h>

namespace Hakurei {
    using namespace eosio;
    using std::string;
    using std::vector;

    class PasswordManager : public contract {
	using contract::contract;

    public:
	PasswordManager(account_name self):contract(self) {}

	//@abi action
	void add(const account_name account, string& __name, string& __passwd) {
		require_auth(account);

		pwIndex passwords(_self, _self);

		string buf;

		uint16_t len_name = htobe16(__name.size());
		uint16_t len_passwd = htobe16(__passwd.size());

		buf.insert(buf.size(), (const char *)&len_name, 2);
		buf.insert(buf.size(), __name.c_str(), __name.size());

		buf.insert(buf.size(), (const char *)&len_passwd, 2);
		buf.insert(buf.size(), __passwd.c_str(), __passwd.size());


		auto it = passwords.find(account);

		if (it != passwords.end()) {
			print("* append\n");
			passwords.modify(it, account, [&](auto& pw_entry) {
			    pw_entry.passwords.push_back(buf);
			});
		} else {
			print("* new\n");
			passwords.emplace(account, [&](auto &pw_entry) {
			    pw_entry.account_name = account;
			    pw_entry.passwords.push_back(buf);
			});
		}
	}

	//@abi action
	void del(const account_name account, string& __name) {
		require_auth(account);

		pwIndex passwords(_self, _self);

		auto it_acct = passwords.find(account);
		eosio_assert(it_acct != passwords.end(), "error: account not found");

		auto cur_acct = passwords.get(account);

		auto &passwds = cur_acct.passwords;

		size_t pos = 0;

		for (auto &it : passwds) {
			uint8_t *pdata = (uint8_t *)it.data();

			uint16_t len_name = be16toh(*(uint16_t *)(pdata));
			uint16_t len_passwd = be16toh(*(uint16_t *)(pdata+2+len_name));

			char *this_name = (char *)malloc(len_name+1);

			this_name[len_name] = 0;

			memcpy(this_name, pdata+2, len_name);

			if (0 == strcmp(__name.c_str(), this_name)) {
				passwords.modify(it_acct, account, [&](auto& pw_entry) {
				    pw_entry.passwords.erase(pw_entry.passwords.begin()+pos);
				});
				print("Deleted \"", (const char *) this_name, "\"\n");
				return;
			}

			free(this_name);

			pos++;
		}

		print("Entry not found: \"", __name.c_str(), "\"\n");

	}

	void get(const account_name account, string& __name) {
		require_auth(account);

		pwIndex passwords(_self, _self);

		auto it = passwords.find(account);
		eosio_assert(it != passwords.end(), "error: account not found");

		auto cur_acct = passwords.get(account);

		auto &passwds = cur_acct.passwords;

		for (auto &it : passwds) {
			uint8_t *pdata = (uint8_t *)it.data();

			uint16_t len_name = be16toh(*(uint16_t *)(pdata));
			uint16_t len_passwd = be16toh(*(uint16_t *)(pdata+2+len_name));

			char *this_name = (char *)malloc(len_name+1);
			char *this_passwd = (char *)malloc(len_passwd+1);

			this_name[len_name] = 0;
			this_passwd[len_passwd] = 0;

			memcpy(this_name, pdata+2, len_name);
			memcpy(this_passwd, pdata+2+len_name+2, len_passwd);

			if (0 == strcmp(__name.c_str(), this_name)) {
				print("Name: ", (const char *)this_name, ", Password: ", (const char *)this_passwd, "\n");
				return;
			}

			free(this_name);
			free(this_passwd);
		}

		print("Entry not found: \"", __name.c_str(), "\"\n");

	}

	//@abi action
	void list(const account_name account) {
		require_auth(account);

		pwIndex passwords(_self, _self);

		auto it = passwords.find(account);
		eosio_assert(it != passwords.end(), "Address for account not found");

		auto cur_acct = passwords.get(account);

		auto &passwds = cur_acct.passwords;

		for (auto &it : passwds) {
			uint8_t *pdata = (uint8_t *)it.data();

			uint16_t len_name = be16toh(*(uint16_t *)(pdata));
			uint16_t len_passwd = be16toh(*(uint16_t *)(pdata+2+len_name));

			char *this_name = (char *)malloc(len_name+1);
			char *this_passwd = (char *)malloc(len_passwd+1);

			this_name[len_name] = 0;
			this_passwd[len_passwd] = 0;

			memcpy(this_name, pdata+2, len_name);
			memcpy(this_passwd, pdata+2+len_name+2, len_passwd);


			print("Name: ", (const char *)this_name, ", Password: ", (const char *)this_passwd, "\n");

			free(this_name);
			free(this_passwd);
		}

	}

    private:

	//@abi table pwentries i64
	struct pw_entry {
		uint64_t account_name;
		vector<string> passwords;
		uint64_t primary_key() const { return account_name; }

		EOSLIB_SERIALIZE(pw_entry, (account_name)(passwords))
	};

	typedef multi_index<N(pw_entry), pw_entry> pwIndex;
    };

    EOSIO_ABI(PasswordManager, (add)(get)(del)(list))
}