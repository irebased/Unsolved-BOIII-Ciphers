#include <openssl/aes.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

static uint64_t factv[15];

static int hv(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  throw std::runtime_error("bad hex");
}
static std::vector<unsigned char> unhex(const std::string& s) {
  if (s.size() % 2) throw std::runtime_error("odd hex");
  std::vector<unsigned char> out;
  out.reserve(s.size()/2);
  for (size_t i=0;i<s.size();i+=2) out.push_back((hv(s[i])<<4)|hv(s[i+1]));
  return out;
}
static std::string hex(const std::vector<unsigned char>& v) {
  static const char* h="0123456789abcdef";
  std::string out; out.reserve(v.size()*2);
  for (auto x:v) { out.push_back(h[x>>4]); out.push_back(h[x&15]); }
  return out;
}

struct AES128 {
  AES_KEY key{};
  AES128() {
    unsigned char k[16]{};
    const unsigned char z[7]={'Z','o','m','b','i','e','s'};
    std::copy(z,z+7,k);
    AES_set_encrypt_key(k,128,&key);
  }
  unsigned char ks0(const std::array<unsigned char,16>& reg) const {
    unsigned char out[16]; AES_encrypt(reg.data(),out,&key); return out[0];
  }
};

static int fsa_step(int state,unsigned char x) {
  if(state==0) {
    if(x==9||x==10||x==13||(x>=32&&x<=126)) return 0;
    if(x==0xe2) return 1;
    return -1;
  }
  if(state==1) return x==0x80 ? 2 : -1;
  if(state==2) return (x==0x93||x==0x94||x==0x98||x==0x99||x==0xa6) ? 0 : -1;
  throw std::runtime_error("bad state");
}
static void shift(std::array<unsigned char,16>& reg,unsigned char cb) {
  for(int i=1;i<16;i++) reg[i-1]=reg[i];
  reg[15]=cb;
}

struct Stats {
  uint64_t nodes=0,rejected_prefix=0,rejected_full=0,rejected_unterminated=0;
  uint64_t accepted_complete=0,rejected_weight=0,terminal_weight=0,maximum_depth=0;
  bool capped=false;
};
struct Solution {
  std::vector<int> order;
  std::vector<unsigned char> plaintext;
};

struct Search {
  std::vector<unsigned char> observed;
  int width,rows;
  char variant;
  uint64_t cap;
  AES128 aes;
  Stats st;
  std::vector<int> slots;
  std::vector<bool> used;
  std::vector<Solution> solutions;

  Search(std::vector<unsigned char> b,int w,char v,uint64_t c)
    :observed(std::move(b)),width(w),variant(v),cap(c),slots(w,-1),used(w,false) {
    if(width<3||width>14||observed.size()%width) throw std::runtime_error("bad shape");
    if(variant!='A'&&variant!='B') throw std::runtime_error("bad variant");
    rows=static_cast<int>(observed.size()/width);
  }
  std::vector<int> order() const {
    std::vector<int> o(width,-1);
    for(int col=0;col<width;col++) o[slots[col]]=col;
    return o;
  }
  std::vector<unsigned char> inverse() const {
    std::vector<unsigned char> out(observed.size());
    auto o=order();
    if(variant=='A') {
      for(int k=0;k<width;k++) for(int r=0;r<rows;r++)
        out[r*width+o[k]]=observed[k*rows+r];
    } else {
      for(int r=0;r<rows;r++) for(int k=0;k<width;k++)
        out[o[k]*rows+r]=observed[r*width+k];
    }
    return out;
  }
  void rec(int depth,int state,std::array<unsigned char,16> reg,
           std::vector<unsigned char>& prefix) {
    if(st.capped) return;
    if(st.nodes>=cap) { st.capped=true; return; }
    st.nodes++;
    st.maximum_depth=std::max<uint64_t>(st.maximum_depth,depth);
    if(depth==width) {
      if(state!=0) {
        st.rejected_unterminated++; st.rejected_weight++; return;
      }
      st.accepted_complete++; st.terminal_weight++;
      solutions.push_back({order(),prefix});
      return;
    }
    for(int rank=0;rank<width;rank++) {
      if(st.capped) return;
      if(used[rank]) continue;
      slots[depth]=rank; used[rank]=true;
      std::vector<unsigned char> emitted;
      if(variant=='A') emitted.push_back(observed[rank*rows]);
      else for(int r=0;r<rows;r++) emitted.push_back(observed[r*width+rank]);
      int ns=state; auto nr=reg; size_t old=prefix.size(); bool ok=true;
      for(auto cb:emitted) {
        unsigned char pb=cb^aes.ks0(nr);
        int q=fsa_step(ns,pb);
        if(q<0) { ok=false; break; }
        ns=q; prefix.push_back(pb); shift(nr,cb);
      }
      int remaining=width-depth-1;
      if(ok&&variant=='A'&&depth+1==width) {
        auto ct=inverse();
        for(size_t i=width;i<ct.size();i++) {
          unsigned char pb=ct[i]^aes.ks0(nr);
          int q=fsa_step(ns,pb);
          if(q<0) { ok=false; st.rejected_full++; break; }
          ns=q; prefix.push_back(pb); shift(nr,ct[i]);
        }
      }
      if(ok) rec(depth+1,ns,nr,prefix);
      else { st.rejected_prefix++; st.rejected_weight+=factv[remaining]; }
      prefix.resize(old); used[rank]=false; slots[depth]=-1;
    }
  }
  void run() {
    std::array<unsigned char,16> iv{}; iv.fill('0');
    std::vector<unsigned char> prefix;
    rec(0,0,iv,prefix);
    uint64_t total=st.rejected_weight+st.terminal_weight;
    if(total>factv[width]) throw std::runtime_error("certificate overflow");
    if(!st.capped&&total!=factv[width]) throw std::runtime_error("incomplete certificate");
  }
};

int main(int argc,char**argv) {
  try {
    if(argc!=5) {
      std::cerr<<"usage: byte_columnar WIDTH VARIANT NODE_LIMIT OBSERVED_HEX\n"; return 2;
    }
    factv[0]=1; for(int i=1;i<=14;i++) factv[i]=factv[i-1]*i;
    int width=std::stoi(argv[1]); char variant=argv[2][0];
    uint64_t cap=std::stoull(argv[3]);
    auto start=std::chrono::steady_clock::now();
    Search s(unhex(argv[4]),width,variant,cap); s.run();
    double sec=std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();
    std::cout<<"{\"identity\":\"ASTRA\",\"width\":"<<width
      <<",\"variant\":\""<<variant<<"\",\"node_limit\":"<<cap
      <<",\"nodes\":"<<s.st.nodes<<",\"rejected_prefix\":"<<s.st.rejected_prefix
      <<",\"rejected_full\":"<<s.st.rejected_full
      <<",\"rejected_unterminated\":"<<s.st.rejected_unterminated
      <<",\"accepted_complete\":"<<s.st.accepted_complete
      <<",\"rejected_weight\":"<<s.st.rejected_weight
      <<",\"terminal_weight\":"<<s.st.terminal_weight
      <<",\"certificate_weight\":"<<(s.st.rejected_weight+s.st.terminal_weight)
      <<",\"expected_weight\":"<<factv[width]
      <<",\"maximum_depth\":"<<s.st.maximum_depth
      <<",\"capped\":"<<(s.st.capped?"true":"false")
      <<",\"elapsed_seconds\":"<<sec<<",\"solutions\":[";
    for(size_t i=0;i<s.solutions.size();i++) {
      if(i) std::cout<<",";
      std::cout<<"{\"order\":[";
      for(int j=0;j<s.width;j++) { if(j)std::cout<<","; std::cout<<s.solutions[i].order[j]; }
      std::cout<<"],\"plaintext_hex\":\""<<hex(s.solutions[i].plaintext)<<"\"}";
    }
    std::cout<<"]}\n";
  } catch(const std::exception& e) {
    std::cerr<<e.what()<<"\n"; return 1;
  }
}
