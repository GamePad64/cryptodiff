/*
 * You may redistribute this program and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#pragma once
#ifndef P2PNET_H_
#define P2PNET_H_

#include <list>
#include <vector>
#include <string>
#include <system_error>

namespace p2pnet {
	namespace crypto {
		struct KeyPair {
			std::string private_key;
			std::string public_key;
		};

		KeyPair genKeyPair();
	}

	struct version_t {
		uint16_t major, minor, patch;
	};

	class Instance {
		class Impl; Impl* pImpl;
	public:
		Instance();
		//Instance(boost::asio::io_service& io_service);	// Only with WITH_ASIO
		~Instance();

		Impl* impl(){return pImpl;};

		version_t version() const;
	};

	class Node {
		class Impl; Impl* pImpl;
	public:
		Node(Instance* instance);
		~Node();

		void bind(std::string private_key);
		std::string privkey();
		std::string pubkey();
		std::string sh();

		int listen(int backlog);

		Socket* accept(std::error_condition& e);	// EAGAIN

		//DHT* getDHT();
		Impl* impl(){return pImpl;};
	};

	class Socket {
		class Impl; Impl* pImpl;
	public:
		Socket(Node* node);
		~Socket();

		enum Type {
			/**
			 * Context, which is treated like stream (with congestion control and so on) with preserving bounds of packets, like SCTP.
			 */
			CTX_SEQPACKET = 0,
			CTX_STREAM = 1,
			CTX_DATAGRAM = 2
		};

		void connect(std::string sh, Type type);

		Impl* impl(){return pImpl;};
	};

	typedef struct {
		enum {
			P2P_POLLIN = 1,
			P2P_POLLOUT = 2,
			P2P_POLLERR = 4
		};
		Socket* ctx;
		short events;
		short revents;
	} p2p_pollitem_t;

	// Polls are really used with Instance() constructor without io_service.
	int poll(std::vector<p2p_pollitem_t>& items);
	int poll(p2p_pollitem_t* items, int nitems);

	version_t lib_version() const;
	version_t inst_version(Instance* instance) const;
}

#endif /* P2PNET_H_ */
