#include <openssl/aes.h>
#include <openssl/blowfish.h>
#include <openssl/des.h>
#include <array>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
extern "C" {
 int rc2_LTX__mcrypt_set_key(uint16_t*,const unsigned char*,unsigned int);
 void rc2_LTX__mcrypt_encrypt(const uint16_t*,uint16_t*);
 int loki97_LTX__mcrypt_set_key(uint32_t*,const uint32_t*,uint32_t);
 void loki97_LTX__mcrypt_encrypt(uint32_t*,uint32_t*);
}
struct Stats {uint64_t nodes=0,rejected_plaintext=0,complete=0,maximum_depth=0;bool aborted=false;uint64_t rejected_weight=0,terminal_weight=0,rejected_unterminated=0;};
struct Solution {std::array<int,16> mapping;std::vector<unsigned char> plaintext;};
static void word_reverse(const unsigned char*in,unsigned char*out){for(int h=0;h<2;h++)for(int j=0;j<4;j++)out[4*h+j]=in[4*h+3-j];}
struct ECB {
 std::string name;size_t block;AES_KEY aes{};BF_KEY bf{};DES_key_schedule des{};std::array<uint16_t,64> rc2{};std::array<uint32_t,96> loki{};
 explicit ECB(const std::string&n):name(n){const unsigned char z[7]={'Z','o','m','b','i','e','s'};
  if(n=="aes128"){unsigned char k[16]={0};memcpy(k,z,7);AES_set_encrypt_key(k,128,&aes);block=16;}
  else if(n=="blowfish"||n=="blowfish_compat"){BF_set_key(&bf,7,z);block=8;}
  else if(n=="des"){DES_cblock k{};memcpy(k,z,7);DES_set_key_unchecked(&k,&des);block=8;}
  else if(n=="rc2"){if(rc2_LTX__mcrypt_set_key(rc2.data(),z,7))throw std::runtime_error("RC2 key");block=8;}
  else if(n=="loki97"){alignas(4) std::array<unsigned char,32>k{};memcpy(k.data(),z,7);if(loki97_LTX__mcrypt_set_key(loki.data(),reinterpret_cast<const uint32_t*>(k.data()),16))throw std::runtime_error("Loki key");block=16;}
  else throw std::runtime_error("bad cipher");}
 void encrypt(const unsigned char*in,unsigned char*out)const{
  if(name=="aes128")AES_encrypt(in,out,&aes);
  else if(name=="blowfish")BF_ecb_encrypt(in,out,&bf,BF_ENCRYPT);
  else if(name=="blowfish_compat"){unsigned char a[8],b[8];word_reverse(in,a);BF_ecb_encrypt(a,b,&bf,BF_ENCRYPT);word_reverse(b,out);}
  else if(name=="des"){DES_cblock a{},b{};memcpy(a,in,8);DES_ecb_encrypt(&a,&b,const_cast<DES_key_schedule*>(&des),DES_ENCRYPT);memcpy(out,b,8);}
  else if(name=="rc2"){memcpy(out,in,8);rc2_LTX__mcrypt_encrypt(rc2.data(),reinterpret_cast<uint16_t*>(out));}
  else{memcpy(out,in,16);loki97_LTX__mcrypt_encrypt(const_cast<uint32_t*>(loki.data()),reinterpret_cast<uint32_t*>(out));}
 }};
static uint64_t fact[17];
static int hv(char c){if(c>='0'&&c<='9')return c-'0';if(c>='A'&&c<='F')return c-'A'+10;if(c>='a'&&c<='f')return c-'a'+10;throw std::runtime_error("bad hex");}
static std::vector<unsigned char> unhex(const std::string&s){if(s.size()%2)throw std::runtime_error("odd hex");std::vector<unsigned char>o;for(size_t i=0;i<s.size();i+=2)o.push_back((hv(s[i])<<4)|hv(s[i+1]));return o;}
static std::string hex(const std::vector<unsigned char>&v){static char h[]="0123456789abcdef";std::string s;for(auto x:v){s+=h[x>>4];s+=h[x&15];}return s;}

struct Search {
 ECB ecb; uint64_t cap; std::vector<std::pair<int,int>> symbols;
 std::array<int,16> mapping; uint16_t used0=0; std::vector<unsigned char> plain;
 std::vector<Solution> sols; Stats st;
 Search(std::string cipher,uint64_t limit,std::string display,std::string seed):ecb(cipher),cap(limit){
  mapping.fill(-1);if(display.size()%2)throw std::runtime_error("odd display");
  for(size_t i=0;i<display.size();i+=2)symbols.push_back({hv(display[i]),hv(display[i+1])});
  if(!seed.empty()&&seed!="-"){std::stringstream ss(seed);std::string q;while(std::getline(ss,q,',')){auto p=q.find(':');if(p==std::string::npos)throw std::runtime_error("bad seed");int d=std::stoi(q.substr(0,p)),a=std::stoi(q.substr(p+1));if(d<0||d>15||a<0||a>15||mapping[d]>=0||(used0&(1u<<a)))throw std::runtime_error("bad seed");mapping[d]=a;used0|=1u<<a;}}
 }
 int transition(int state,unsigned char value) const {
  if(state==0){if(value==9||value==10||value==13||(value>=32&&value<=126))return 0;return value==0xe2?1:-1;}
  if(state==1)return value==0x80?2:-1;
  if(state==2)return (value==0x93||value==0x94||value==0x98||value==0x99||value==0xa6)?0:-1;
  throw std::runtime_error("bad endpoint state");
 }
 void rec(size_t pos,std::array<unsigned char,16> reg,uint16_t used,int endpoint){
  if(st.aborted)return;if(st.nodes>=cap){st.aborted=true;return;}
  st.nodes++;st.maximum_depth=std::max<uint64_t>(st.maximum_depth,pos);
  if(pos==symbols.size()){
   int rem=16-__builtin_popcount(used);
   if(endpoint!=0){st.rejected_unterminated++;st.rejected_weight+=fact[rem];return;}
   st.complete++;st.terminal_weight+=fact[rem];sols.push_back({mapping,plain});return;
  }
  int hs=symbols[pos].first,ls=symbols[pos].second,hc=mapping[hs],lc=mapping[ls];
  unsigned char out[16];ecb.encrypt(reg.data(),out);unsigned char ks=out[0];
  auto attempt=[&](int hi,int lo){
   bool ah=hc<0,al=lc<0&&ls!=hs;if(ah)mapping[hs]=hi;if(al)mapping[ls]=lo;
   uint16_t nu=used;if(ah)nu|=1u<<hi;if(al)nu|=1u<<lo;
   unsigned char cb=(hi<<4)|lo,pb=cb^ks;int next=transition(endpoint,pb);
   if(next>=0){plain.push_back(pb);auto nr=reg;for(size_t i=1;i<ecb.block;i++)nr[i-1]=nr[i];nr[ecb.block-1]=cb;rec(pos+1,nr,nu,next);plain.pop_back();}
   else {st.rejected_plaintext++;st.rejected_weight+=fact[16-__builtin_popcount(nu)];}
   if(ah)mapping[hs]=-1;if(al)mapping[ls]=-1;
  };
  if(hs==ls){if(hc>=0)attempt(hc,hc);else for(int v=0;v<16;v++)if(!(used&(1u<<v)))attempt(v,v);}
  else if(hc>=0&&lc>=0)attempt(hc,lc);
  else if(hc>=0){for(int v=0;v<16;v++)if(!(used&(1u<<v)))attempt(hc,v);}
  else if(lc>=0){for(int v=0;v<16;v++)if(!(used&(1u<<v)))attempt(v,lc);}
  else for(int a=0;a<16;a++)if(!(used&(1u<<a)))for(int b=0;b<16;b++)if(b!=a&&!(used&(1u<<b)))attempt(a,b);
 }
 void run(){std::array<unsigned char,16>iv{};for(size_t i=0;i<ecb.block;i++)iv[i]='0';rec(0,iv,used0,0);}
};
static std::vector<unsigned char> cfb8(const std::vector<unsigned char>&in,const ECB&e,bool decrypt){
 std::array<unsigned char,16>reg{};for(size_t i=0;i<e.block;i++)reg[i]='0';std::vector<unsigned char>out;
 for(auto x:in){unsigned char b[16];e.encrypt(reg.data(),b);unsigned char y=x^b[0],ct=decrypt?x:y;out.push_back(y);for(size_t i=1;i<e.block;i++)reg[i-1]=reg[i];reg[e.block-1]=ct;}return out;
}
int main(int argc,char**argv){
 try{
  if(argc==4&&(std::string(argv[1])=="--cfb-encrypt"||std::string(argv[1])=="--cfb-decrypt")){ECB e(argv[2]);auto in=unhex(argv[3]);std::cout<<hex(cfb8(in,e,std::string(argv[1])=="--cfb-decrypt"))<<"\n";return 0;}
  if(argc<4){std::cerr<<"usage: native_text5 CIPHER CAP DISPLAYHEX [SEED]\n";return 2;}
  fact[0]=1;for(int i=1;i<=16;i++)fact[i]=fact[i-1]*i;
  auto start=std::chrono::steady_clock::now();Search s(argv[1],std::stoull(argv[2]),argv[3],argc>4?argv[4]:"-");s.run();
  double sec=std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();
  std::cout<<"{\"identity\":\"ASTRA\",\"cipher\":\""<<argv[1]<<"\",\"node_limit\":"<<s.cap
   <<",\"nodes\":"<<s.st.nodes<<",\"rejected_plaintext\":"<<s.st.rejected_plaintext
   <<",\"complete\":"<<s.st.complete<<",\"maximum_depth\":"<<s.st.maximum_depth
   <<",\"aborted_at_node_limit\":"<<(s.st.aborted?"true":"false")
   <<",\"expected_completion_weight\":"<<fact[16-__builtin_popcount(s.used0)]
   <<",\"certificate_weight\":"<<(s.st.rejected_weight+s.st.terminal_weight)
   <<",\"rejected_completion_weight\":"<<s.st.rejected_weight
   <<",\"terminal_completion_weight\":"<<s.st.terminal_weight
   <<",\"rejected_unterminated_endpoint\":"<<s.st.rejected_unterminated
   <<",\"elapsed_seconds\":"<<sec<<",\"solutions\":[";
  for(size_t i=0;i<s.sols.size();i++){if(i)std::cout<<",";std::cout<<"{\"mapping\":[";for(int j=0;j<16;j++){if(j)std::cout<<",";std::cout<<s.sols[i].mapping[j];}std::cout<<"],\"plaintext_hex\":\""<<hex(s.sols[i].plaintext)<<"\"}";}
  std::cout<<"]}\n";
 }catch(const std::exception&e){std::cerr<<e.what()<<"\n";return 1;}
}
