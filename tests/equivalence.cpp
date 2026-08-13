#include "pvcrotsymenc1/symmetric_encryption.hpp"
#include "pvcaead0/aead.hpp"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {
std::uint64_t next(std::uint64_t& s) { s ^= s<<13U; s ^= s>>7U; s ^= s<<17U; return s; }
std::vector<std::uint8_t> bytes(std::uint64_t& s,std::size_t n){ std::vector<std::uint8_t> v(n); for(auto& b:v)b=static_cast<std::uint8_t>(next(s)&0xffU); return v; }
}
int main(int argc,char** argv){
    std::size_t count=512U; if(argc==3&&std::string(argv[1])=="--count") count=static_cast<std::size_t>(std::strtoull(argv[2],nullptr,10));
    std::uint64_t s=0x5253594d454e4331ULL;
    for(std::size_t c=0;c<count;++c){
        pvcrotsymenc1::KeyPair512 rk{}; pvcaead0::KeyPair512 ak{}; pvcrotsymenc1::Nonce192 rn{}; pvcaead0::Nonce192 an{};
        for(std::size_t i=0;i<32U;++i){ rk.encryption_key[i]=static_cast<std::uint8_t>(next(s)); rk.authentication_key[i]=static_cast<std::uint8_t>(next(s)); }
        ak.encryption_key=rk.encryption_key; ak.authentication_key=rk.authentication_key;
        for(std::size_t i=0;i<24U;++i) {
            rn[i]=static_cast<std::uint8_t>(next(s));
        }
        an=rn;
        const auto ad=bytes(s,static_cast<std::size_t>(next(s)%33U)); const auto p=bytes(s,static_cast<std::size_t>(next(s)%97U));
        const auto selector=static_cast<unsigned>(next(s)%3U);
        const auto rt=selector==0U?pvcrotsymenc1::TagSize::Bits128:selector==1U?pvcrotsymenc1::TagSize::Bits192:pvcrotsymenc1::TagSize::Bits256;
        const auto at=selector==0U?pvcaead0::TagSize::Bits128:selector==1U?pvcaead0::TagSize::Bits192:pvcaead0::TagSize::Bits256;
        const auto r=pvcrotsymenc1::seal(rk,rn,ad,p,rt); const auto a=pvcaead0::seal(ak,an,ad,p,at);
        if(r.ciphertext!=a.ciphertext||r.tag!=a.tag){std::cerr<<"mismatch case="<<c<<'\n';return 1;}
        const auto ro=pvcrotsymenc1::open(rk,rn,ad,r.ciphertext,r.tag); const auto ao=pvcaead0::open(ak,an,ad,a.ciphertext,a.tag);
        if(!ro||!ao||*ro!=p||*ao!=p){std::cerr<<"open mismatch case="<<c<<'\n';return 1;}
    }
    std::cout<<"equivalence_cases="<<count<<" mismatches=0\n"; return 0;
}
