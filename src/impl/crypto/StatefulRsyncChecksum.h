/* Copyright (C) 2014-2015 Alexander Shishenko <GamePad64@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#pragma once

#include "RsyncChecksum.h"
#include <boost/circular_buffer.hpp>

class StatefulRsyncChecksum {
	RsyncChecksum checksum_;
	boost::circular_buffer<uint8_t> state_buffer_;
public:
	StatefulRsyncChecksum() {}
	template<class InputIterator> StatefulRsyncChecksum(InputIterator first, InputIterator last) : StatefulRsyncChecksum(){compute(first, last);}

	operator weakhash_t() const {return checksum_;}
	operator RsyncChecksum() const {return checksum_;};

	/**
	 * Computation itself. Based on work of Donovan Baarda <abo@minkirri.apana.org.au>. Code modified from librsync.
	 * @param source
	 * @param len
	 * @return
	 */
	template<class InputIterator> weakhash_t compute(InputIterator first, InputIterator last){
		state_buffer_.assign(first, last);
		return checksum_.compute(first, last);
	}

	weakhash_t roll(uint8_t in){
		uint8_t front = state_buffer_.front();
		state_buffer_.push_back(in);
		return checksum_.roll(front, in);
	}

	const boost::circular_buffer<uint8_t>& state_buffer() const {return state_buffer_;}
};
