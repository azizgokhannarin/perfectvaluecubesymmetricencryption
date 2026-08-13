#include "pvcrotsymenc1/symmetric_encryption.hpp"
#include "pvcaead0/aead.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using namespace pvcrotsymenc1;
KeyPair512 keys() {
    KeyPair512 k{};
    for (std::size_t i=0;i<32U;++i) { k.encryption_key[i]=static_cast<std::uint8_t>(i); k.authentication_key[i]=static_cast<std::uint8_t>(0x80U+i); }
    return k;
}
Nonce192 nonce() { return {}; }
std::vector<std::uint8_t> hex(const std::string& s) {
    auto n=[](char c)->std::uint8_t{ if(c>='0'&&c<='9')return static_cast<std::uint8_t>(c-'0'); if(c>='a'&&c<='f')return static_cast<std::uint8_t>(10+c-'a'); throw std::runtime_error("hex");};
    std::vector<std::uint8_t> out(s.size()/2U); for(std::size_t i=0;i<out.size();++i) out[i]=static_cast<std::uint8_t>((n(s[2*i])<<4U)|n(s[2*i+1])); return out;
}
bool canonical() {
    const std::vector<std::uint8_t> p{'a','b','c'};
    const auto s=seal(keys(),nonce(),{},p,TagSize::Bits256);
    return s.ciphertext==hex("a10b4d") && s.tag==hex("a16ff4b4dd13b48bab0701cd8a67f1248ebb4bf37a3146931f04e08c834d5cee");
}
bool roundtrip() {
    const std::vector<std::uint8_t> ad{0,1,2,0xff}; const std::vector<std::uint8_t> p{0,1,0,2,3,4,0xff};
    const auto s=seal(keys(),nonce(),ad,p,TagSize::Bits192); const auto o=open(keys(),nonce(),ad,s.ciphertext,s.tag); return o && *o==p;
}
bool tamper() {
    const std::vector<std::uint8_t> p{1,2,3,4}; const auto s=seal(keys(),nonce(),{},p,TagSize::Bits128); auto t=s.tag; t[0]^=1U; return !open(keys(),nonce(),{},s.ciphertext,t);
}
bool invalid() { try { (void)tag_size_from_bytes(20U); return false; } catch(const std::invalid_argument&) { return true; } }
bool equivalence() {
    const std::vector<std::uint8_t> ad{0x42}; const std::vector<std::uint8_t> p{1,2,3,4,5};
    const auto r=seal(keys(),nonce(),ad,p,TagSize::Bits256);
    const pvcaead0::KeyPair512 ak{keys().encryption_key,keys().authentication_key}; const pvcaead0::Nonce192 an{};
    const auto a=pvcaead0::seal(ak,an,ad,p,pvcaead0::TagSize::Bits256); return r.ciphertext==a.ciphertext && r.tag==a.tag;
}
}
int main(int argc,char** argv){ if(argc!=3||std::string(argv[1])!="--case") return 2; const std::string c=argv[2]; bool ok=false; if(c=="canonical-vector")ok=canonical(); else if(c=="roundtrip")ok=roundtrip(); else if(c=="tamper-reject")ok=tamper(); else if(c=="tag-profile-invalid")ok=invalid(); else if(c=="a1-byte-equivalence")ok=equivalence(); else return 2; if(!ok){std::cerr<<"FAIL "<<c<<'\n';return 1;} std::cout<<"PASS "<<c<<'\n';return 0; }
