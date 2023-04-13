#include<iostream>
#include "cryptopp/cryptlib.h"
#include "cryptopp/rijndael.h"
#include "cryptopp/modes.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include "cryptopp/aes.h"
#include "cryptopp/filters.h"
#include "cryptopp/gcm.h"
#include"cryptopp/rdrand.h"
#include <openssl/sha.h>
#include<bits/stdc++.h>
#include <pbc.h>
#include <ctime>

using namespace std;
using namespace CryptoPP;
using byte = unsigned char ;

struct hash_pair {
    template <class T1, class T2>
    size_t operator()(const pair<T1, T2>& p) const
    {
        auto hash1 = hash<T1>{}(p.first);
        auto hash2 = hash<T2>{}(p.second);
 
        if (hash1 != hash2) {
            return hash1 ^ hash2;             
        }
          return hash1;
    }
};
unordered_map<int, pair<unsigned char *,int>> point_to_key;
void print_text(byte text[],int size){
    string encoded;

    encoded.clear();
	StringSource(text, size, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "Hexcoded: " << encoded << endl;
}
template< typename T > std::array< byte, sizeof(T) >  to_bytes( const T& object )
{
    std::array< byte, sizeof(T) > bytes ;

    const byte* begin = reinterpret_cast< const byte* >( std::addressof(object) ) ;
    const byte* end = begin + sizeof(T) ;
    std::copy( begin, end, std::begin(bytes) ) ;

    return bytes ;
}

pair<byte*, int> convert_to_byte(tuple<element_s,int, tuple<int,int,pair<element_s, element_s>>,element_s, element_s,vector<element_s>> c){
    element_s u = get<0>(c);
    int size_u = element_length_in_bytes(&u);
    byte byte_u[size_u]; element_to_bytes(byte_u,&u);
   // print_text(byte_u,size_u);
    int A = get<1>(c);
    int size_A = sizeof(A);
    byte byte_A[size_A]; memcpy(byte_A, (const void*)&A,size_A);
   // print_text(byte_A,size_A);
    int z = get<0>(get<2>(c));
    int size_z = sizeof(z);
    byte byte_z[size_z]; memcpy(byte_z, (const void*)&z,size_z);
  //  print_text(byte_z,size_z);
    int e = get<1>(get<2>(c));
    int size_e = sizeof(e);
    byte byte_e[size_e];memcpy(byte_e, (const void*)&e,size_e);
   // print_text(byte_e,size_e);
    element_s m_1 = get<2>(get<2>(c)).first;
    int size_m_1 = element_length_in_bytes(&m_1);
    byte byte_m_1[size_m_1]; element_to_bytes(byte_m_1,&m_1);
   // print_text(byte_m_1,size_m_1);
    element_s m_2 = get<2>(get<2>(c)).second;
    int size_m_2 = element_length_in_bytes(&m_2);
    byte byte_m_2[size_m_2]; element_to_bytes(byte_m_2,&m_2);
    //print_text(byte_m_2,size_m_2);
    element_s sig_1 = get<3>(c);
    int size_sig_1 = element_length_in_bytes(&sig_1);
    byte byte_sig_1[size_sig_1]; element_to_bytes(byte_sig_1,&sig_1);
  //  print_text(byte_sig_1,size_sig_1);
    element_s sig_2 = get<4>(c);
    int size_sig_2 = element_length_in_bytes(&sig_2);
    byte byte_sig_2[size_sig_2]; element_to_bytes(byte_sig_2,&sig_2);
  //  print_text(byte_sig_2,size_sig_2);
    element_s pk = get<5>(c).at(0);
    int size_pk = element_length_in_bytes(&pk);
    byte byte_pk[size_pk];element_to_bytes(byte_pk,&pk);
   // print_text(byte_pk,size_pk);
    int total_size = size_u + size_A + size_z + size_e + size_m_1 + size_m_2 + size_sig_1 + size_sig_2 + (size_pk*get<5>(c).size());
    byte* final_arr = new byte[total_size];
    bzero(final_arr,total_size);
    memcpy(final_arr,byte_u,size_u);memcpy(final_arr+size_u,byte_A,size_A);
    memcpy(final_arr+size_u+size_A,byte_z,size_z);memcpy(final_arr+size_u+size_A + size_z,byte_e,size_e);
    memcpy(final_arr+size_u+size_A + size_z + size_e ,byte_m_1,size_m_1);memcpy(final_arr+size_u+size_A + size_z + size_e + size_m_1,byte_m_2,size_m_2);
    memcpy(final_arr+size_u+size_A + size_z + size_e + size_m_1 + size_m_2,byte_sig_1,size_sig_1);memcpy(final_arr+size_u+size_A + size_z + size_e + size_m_1 + size_m_2 + size_sig_1,byte_sig_2,size_sig_2);
    int j = size_u+size_A + size_z + size_e + size_m_1 + size_m_2 + size_sig_1 + size_sig_2;
    for(auto i = get<5>(c).begin(); i!=get<5>(c).end();i++){
            element_s pk1 = *i;
            int size_pk1 = element_length_in_bytes(&pk1);
            byte byte_pk1[size_pk1];element_to_bytes(byte_pk1,&pk1);
            memcpy(final_arr+j,byte_pk1,size_pk1);
            //print_text(byte_pk1,size_pk1);
            j=j+size_pk1;
    }
   // print_text(final_arr,total_size);
    return make_pair(final_arr, total_size);
}

template< typename T >
T& from_bytes( const std::array< byte, sizeof(T) >& bytes, T& object )
{
    static_assert( std::is_trivially_copyable<T>::value, "not a TriviallyCopyable type" ) ;

    byte* begin_object = reinterpret_cast< byte* >( std::addressof(object) ) ;
    std::copy( std::begin(bytes), std::end(bytes), begin_object ) ;

    return object ;
}


struct pp_sig{
    pairing_s pairing;
    element_s g;
    
    void init(){
        char param[1024];
        FILE *stream = fopen("a.param", "r");
        size_t count = fread(param, 1, 1024, stream);
        if (!count) pbc_die("input error");
        pairing_init_set_buf(&pairing, param, count);
        element_init_G2(&g, &pairing);
    }
};

struct pp_dgsa{
    pairing_s pairing;
    element_s g;
    
    void init(){
        char param[1024];
        FILE *stream = fopen("a.param", "r");
        size_t count = fread(param, 1, 1024, stream);
        if (!count) pbc_die("input error");
        pairing_init_set_buf(&pairing, param, count);
        element_init_G2(&g, &pairing);
    
    }
};
struct pp_pke{
    pairing_s pairing;
    element_s g;

    void init(){
        char param[1024];
        FILE *stream = fopen("a.param", "r");
        size_t count = fread(param, 1, 1024, stream);
        if (!count) pbc_die("input error");
        pairing_init_set_buf(&pairing, param, count);
        element_init_GT(&g, &pairing);
    }

};
struct pp_se{
    AutoSeededRandomPool prng;
    int key_size;
    void init(){
        key_size = AES::DEFAULT_KEYLENGTH;
    }
};
class SE{
    public:
    pp_se params;
    SE(){params.init();}

    byte key_gen(){
        byte Kp[params.key_size];
	    params.prng.GenerateBlock(Kp, sizeof(Kp));
        return *Kp;
    }
    pair<ByteQueue, byte> Enc(byte* Kp,int kp_size, byte* P, int payload_size){
        byte iv[AES::BLOCKSIZE];
	    params.prng.GenerateBlock(iv, sizeof(iv));

        ByteQueue plain, cipher;
        plain.Put(P,payload_size);
        try
	    {
		    //cout << "plain text: " << payload << endl;
		    CTR_Mode< AES >::Encryption e;
		    e.SetKeyWithIV(Kp, kp_size, iv);

	        StreamTransformationFilter f1(e,new Redirector(cipher));
            plain.CopyTo(f1);
            f1.MessageEnd();

	    }
	    catch(const CryptoPP::Exception& e)
	    {
		    cerr << e.what() << endl;
		    exit(1);
	    }

        return make_pair(cipher, *iv);
    }
    byte* Dec(byte* Kp, byte* ct, int size){
        
    }


};
class PKE{
    public:
    pp_pke params;
    PKE(){params.init();
    element_random(&params.g);
    }
    pair<element_s, element_s> pke_key_gen(){
        element_s pk,sk;
        element_init_GT(&pk, &params.pairing);
        element_init_Zr(&sk, &params.pairing);
        element_random(&sk);
        element_pow_zn(&pk, &params.g, &sk);
        return make_pair(pk,sk);
    }
    pair<element_s, element_s> pke_enc(element_s pk, element_s message){
         char ans[1000];
         element_s ciphertext1, ciphertext2, k;
         element_init_GT(&ciphertext1, &params.pairing);
         element_init_GT(&ciphertext2, &params.pairing);
         element_init_Zr(&k, &params.pairing);
         element_random(&k);
         
         element_pow_zn(&ciphertext1,&params.g, &k);
         
         element_pow_zn(&ciphertext2,&pk, &k);
         
         element_mul(&ciphertext2, &ciphertext2, &message);
    
         return make_pair(ciphertext1, ciphertext2);
    }
    element_s pke_dec(element_s sk, pair<element_s, element_s> cipher){
        element_s m_decrypted;
        element_init_GT(&m_decrypted, &params.pairing);
        element_pow_zn(&m_decrypted, &cipher.first, &sk);
        element_invert(&m_decrypted, &m_decrypted);
        element_mul(&m_decrypted, &m_decrypted, &cipher.second);

        return m_decrypted;
    }
};
class BLS{
    public:
    pp_sig params;
    BLS(){params.init();}
    pair<element_s,element_s> bls_key_gen(){
        element_s vk, sk;
        element_init_Zr(&sk, &params.pairing);
        element_init_G2(&vk, &params.pairing);

        element_random(&params.g);
        element_random(&sk);
        element_pow_zn(&vk, &params.g, &sk);

        return make_pair(vk,sk);
    }
    element_s bls_sign(element_s sk, unsigned char * message,int size){
        element_s sig,h;
        element_init_G1(&sig, &params.pairing);
        element_init_G1(&h, &params.pairing);
        element_from_hash(&h, message, size);

        element_pow_zn(&sig, &h, &sk);

        return sig;
    }
    bool bls_verify(element_s pk, unsigned char* message, int size, element_s sig){
        element_s temp1,temp2;
        element_init_GT(&temp1, &params.pairing);
        element_init_GT(&temp2, &params.pairing);
        pairing_apply(&temp1, &sig, &params.g, &params.pairing);
    
        element_s h;
        element_init_G1(&h, &params.pairing);
        element_from_hash(&h, message, size);
        pairing_apply(&temp2, &h, &pk, &params.pairing);
        char ans[1000];
        // element_snprint(ans,sizeof(ans),&temp1);
        // cout<<"bls_verify = "<<string(ans)<<endl;
        // element_snprint(ans,sizeof(ans),&temp2);
        // cout<<"y = "<<string(ans)<<endl;
        return !element_cmp(&temp1, &temp2);
    }
};
class PS{
    public:
    pp_dgsa params;
    PS(){params.init();}
    pair<vector<element_s>,vector<element_s>> ps_key_gen(int number_of_attributes){
        vector<element_s> vk;
        vector<element_s> sk;
        element_s x, id;
        element_init_Zr(&x, &params.pairing);
        element_init_Zr(&id, &params.pairing);
        element_random(&x);
        element_random(&id);
        element_random(&params.g);
        sk.push_back(x);
        sk.push_back(id);
        vk.push_back(params.g);
        
        for(int i=0;i<=number_of_attributes;i++){
            element_s y;
            element_init_Zr(&y,&params.pairing);
            element_random(&y);
            sk.push_back(y);
        }

        // char ans[1000];
        // element_snprint(ans,sizeof(ans),&sk[0]);
        // cout<<"x = "<<string(ans)<<endl;
        // element_snprint(ans,sizeof(ans),&sk[1]);
        // cout<<"y = "<<string(ans)<<endl;
        // element_snprint(ans,sizeof(ans),&sk[2]);
        // cout<<"y = "<<string(ans)<<endl;
        
        element_s X, Y_id;
        element_init_G2(&X, &params.pairing);
        element_pow_zn(&X,&vk[0],&sk[0]);
        vk.push_back(X);
        element_init_G2(&Y_id, &params.pairing);
        element_pow_zn(&Y_id,&vk[0],&sk[1]);
        vk.push_back(Y_id);

        for(int i=0;i<=number_of_attributes;i++){
            element_s Y;
            element_init_G2(&Y,&params.pairing);
            element_pow_zn(&Y,&vk[0],&sk[i+2]);
            vk.push_back(Y);
        }

        return make_pair(vk,sk);

    }

    pair<vector<element_s>,vector<element_s>> ps_key_gen_vehicle(int V,int number_of_attributes){
        vector<element_s> vk;
        vector<element_s> sk;
        element_s x, y_id;
        element_init_Zr(&x, &params.pairing);
        element_init_Zr(&y_id, &params.pairing);
        element_random(&x);
        element_random(&params.g);
        element_set_si(&y_id,V);
        sk.push_back(x);
        sk.push_back(y_id);
        vk.push_back(params.g);
        
        for(int i=0;i<=number_of_attributes;i++){
            element_s y;
            element_init_Zr(&y,&params.pairing);
            element_random(&y);
            sk.push_back(y);
        }

        // char ans[1000];
        // element_snprint(ans,sizeof(ans),&sk[0]);
        // cout<<"x = "<<string(ans)<<endl;
        // element_snprint(ans,sizeof(ans),&sk[1]);
        // cout<<"y = "<<string(ans)<<endl;
        // element_snprint(ans,sizeof(ans),&sk[2]);
        // cout<<"y = "<<string(ans)<<endl;
        
        element_s X;
        element_init_G2(&X, &params.pairing);
        element_pow_zn(&X,&vk[0],&sk[0]);
        vk.push_back(X);

        for(int i=0;i<=number_of_attributes;i++){
            element_s Y;
            element_init_G2(&Y,&params.pairing);
            element_pow_zn(&Y,&vk[0],&sk[i+1]);
            vk.push_back(Y);
        }

        return make_pair(vk,sk);

    }
    pair<pair<element_s,element_s>,element_s> ps_sign(vector<element_s> sk, vector<element_s> message){
       element_s sum;
       element_init_Zr(&sum,&params.pairing);
       element_add(&sum,&sum,&sk[0]);
       for(int i=0;i<message.size();i++){
            element_s temp,h;
            element_init_Zr(&temp, &params.pairing);
            element_init_Zr(&h, &params.pairing);
            // cout<<size[i]<<endl;
            //print_text(message[i], size[i]);
            element_mul_zn(&temp,&message[i],&sk[i+1]);
            element_add(&sum,&sum,&temp);
       }
        element_s temp,m_dash, h;
        element_init_G1(&h,&params.pairing);
        element_init_Zr(&temp, &params.pairing);
        element_random(&h);
        element_init_Zr(&m_dash,&params.pairing);
        element_random(&m_dash);
        element_mul_zn(&temp,&m_dash,&sk[sk.size()-1]);
        element_add(&sum,&sum,&temp);

        element_s sig;
        element_init_G1(&sig, &params.pairing);
        element_pow_zn(&sig,&h,&sum);
        // char ans[1000];
        // element_snprint(ans,sizeof(ans),&sig);
        // cout<<"sig = "<<string(ans)<<endl;
        // element_snprint(ans,sizeof(ans),&m_dash);
        // cout<<"m_dash = "<<string(ans)<<endl;
        // element_snprint(ans,sizeof(ans),&h);
        // cout<<"h = "<<string(ans)<<endl;
        element_printf("sigma_1 = %B\n\n",&h);
        element_printf("sigma_2 = %B\n\n",&sig);
        element_printf("m_dash = %B\n\n",&m_dash);
        return make_pair(make_pair(m_dash,h),sig);

    }
    bool ps_verify(vector<element_s> vk, vector<element_s> message, pair<pair<element_s,element_s>,element_s> sig){
       element_s mult;
       element_init_G2(&mult,&params.pairing);
       
        for(int i=0;i<message.size();i++){
            element_s temp;
            element_init_G2(&temp,&params.pairing);
            if(i==0){
                //print_text(message[i], size[i]);
                element_pow_zn(&temp,&vk[2],&message[i]);
                element_mul(&mult,&temp,&vk[1]);
            }
            else{
            //print_text(message[i], size[i]);
            element_pow_zn(&temp,&vk[i+2],&message[i]);
            element_mul(&mult,&mult, &temp);
            }
       }

       element_s temp;
       element_init_G2(&temp,&params.pairing);
       element_pow_zn(&temp,&vk[vk.size()-1],&sig.first.first);
       element_mul(&mult, &mult,&temp);

        element_s pai1,pai2;
        element_init_GT(&pai1,&params.pairing);
        element_init_GT(&pai2,&params.pairing);

        pairing_apply(&pai1,&sig.first.second,&mult,&params.pairing);

        pairing_apply(&pai2,&sig.second,&vk[0] ,&params.pairing);

        // char ans[1000];
        // element_snprint(ans,sizeof(ans),&pai1);
        // cout<<"x = "<<string(ans)<<endl;
        // element_snprint(ans,sizeof(ans),&pai2);
        // cout<<"y = "<<string(ans)<<endl;

        if (!element_cmp(&pai1, &pai2)) {
            printf("signature verifies\n");
            return true;
        } else {
            printf("signature does not verify\n");
            return false;
        }
    }

};

class Issuer{
    private:
    vector<element_s> sk_i;
    BLS bls_e;
    struct hashFunction
    {
        size_t operator()(const tuple<int,int>&x) const{
        return get<0>(x) ^ get<1>(x);
        }
    };
    unordered_map<tuple<int,int>,element_s, hashFunction> st_i;

    public:
    vector<element_s> pk_i;
    PS ps;
    Issuer(BLS b){
        this->bls_e = b;
    }
    
    void key_gen_i(){
        pair<vector<element_s>, vector<element_s>> s = ps.ps_key_gen(1);
        sk_i = s.second; pk_i = s.first;

    }

    bool check_vehicle_cred(pair<pair<element_s,element_s>,element_s> cred, int V, int epoch, BLS bls_v, element_s pk_e){
            
            
            int size_int = sizeof(V);
            int size_vk_v = element_length_in_bytes(&cred.first.first);
            //cout<<sizeof(V)<<"   "<<size_vk_v<<endl;
            byte serialize[size_int+size_vk_v];
            bzero(serialize, size_int+size_vk_v);
            memcpy(serialize, (const void*)&V,size_int);
            //print_text(serialize,sizeof(V));
            byte el[size_vk_v]; element_to_bytes(el,&cred.first.first);
            //print_text(el,size_vk_v);
            memcpy(serialize+size_int,el,size_vk_v);
            // cout<<"This is check"<<endl;
            // print_text(serialize,sizeof(V)+size_vk_v);
            byte serialize2[size_int];
            memcpy(serialize2, (const void*)&epoch,size_int);
            //print_text(serialize2,sizeof(epoch));
            return bls_e.bls_verify(pk_e,serialize, sizeof(serialize),cred.first.second)
                    && bls_v.bls_verify(cred.first.first, serialize2, sizeof(serialize2),cred.second);
    }
    pair<pair<element_s,element_s>,element_s> DGSA_issuance_i(int V, int epoch){
            if(st_i.find(make_tuple(V,epoch)) != st_i.end()){
                cout<<"Vehicle with same id and epoch number already exists"<<endl;
                exit(1);
            }
            vector<element_s> message;
            element_s v_id, epoch_s;
            element_init_Zr(&v_id, &ps.params.pairing);
            element_init_Zr(&epoch_s, &ps.params.pairing);
            element_set_si(&v_id, V);
            element_set_si(&epoch_s, epoch);

            //print_text(serialize, size_int);
            //print_text(serialize2, size_int2);
            //auto serialized1 = to_bytes(V); auto serialized2 = to_bytes(epoch);
            message.push_back(v_id);
            message.push_back(epoch_s);
            pair<pair<element_s,element_s>,element_s> sign = ps.ps_sign(sk_i,message);
            st_i.insert(make_pair(make_tuple(V,epoch), sign.first.first));
            return sign;
    }

};

class Enrollment_authority{
    private:
    element_s sk_e;
    unordered_set <int> st_e;

    public:
    element_s pk_e;
    BLS bls;

    void key_gen_e(){
        pair<element_s, element_s> s = bls.bls_key_gen();
        pk_e = s.first;
        sk_e = s.second;
    }
    element_s enroll_vehicle(int V, element_s vk_v){
        if(st_e.find(V) != st_e.end()){
            cout<<"Vehicle already enrolled"<<endl;
            exit(1);
        }
        int size_int = sizeof(V);
        int size_vk_v = element_length_in_bytes(&vk_v);
        //cout<<sizeof(V)<<"   "<<size_vk_v<<endl;
        byte serialize[sizeof(V)+size_vk_v];
        bzero(serialize, sizeof(V)+size_vk_v);
        memcpy(serialize, (const void*)&V,sizeof(V));
        //print_text(serialize,sizeof(V));
        byte el[size_vk_v]; element_to_bytes(el,&vk_v);
        //print_text(el,size_vk_v);
        memcpy(serialize+sizeof(V),el,size_vk_v);
        //print_text(serialize,sizeof(V)+size_vk_v);
        element_s sig = bls.bls_sign(sk_e,serialize,sizeof(serialize));
        st_e.insert(V);
        return sig;
    }
};

class Vehicle{
    private:
    element_s sk_v;
    BLS bls_e;
    PKE pke_v;
    unordered_map<pair<int, int>, pair<unsigned char *,int>, hash_pair> Lk;
    element_s pke_private;
    public:
    element_s vk_v;
    element_s pk_e;
    element_s pke_public;
    
    BLS bls;
    PS ps_i;
    int V;
    Vehicle(BLS bls_e, PS iss, PKE pk){
        this->bls_e = bls_e;
        this->ps_i = iss;
        this->pke_v = pk;
        pair<element_s, element_s> s = pke_v.pke_key_gen();
        pke_public = s.first;
        pke_private = s.second;
    }

    pair<int, element_s> enroll(element_s pk,int vehicle_id){
        pk_e = pk;
        V=vehicle_id;
        pair<element_s,element_s> s = bls.bls_key_gen();
        vk_v = s.first; sk_v = s.second;
        return make_pair(vehicle_id,vk_v);
    }
    pair<pair<element_s,element_s>,element_s> generate_cert(element_s sig_e){
        int size_int = sizeof(V);
        int size_vk_v = element_length_in_bytes(&vk_v);
        //cout<<sizeof(V)<<"   "<<size_vk_v<<endl;
        byte serialize[size_int+size_vk_v];
        bzero(serialize, size_int+size_vk_v);
        memcpy(serialize, (const void*)&V,size_int);
        //print_text(serialize,sizeof(V));
        byte el[size_vk_v]; element_to_bytes(el,&vk_v);
        //print_text(el,size_vk_v);
        memcpy(serialize+size_int,el,size_vk_v);
        //print_text(serialize,sizeof(V)+ size_vk_v);
        if(bls_e.bls_verify(pk_e,serialize, sizeof(serialize),sig_e)){
            cout<<"verification passed!"<<endl;
        }
        else {
            cout<<"failure"<<endl;
            exit(1);
        }
        return make_pair(make_pair(sk_v, vk_v), sig_e);
    }

    pair<pair<element_s,element_s>,element_s> gen_cred_for_authorization(pair<pair<element_s,element_s>,element_s> cert_v, int epoch){ //include public key of issuer as argument
        element_s sig_e = cert_v.second;
       
        int size_int = sizeof(epoch);
        byte serialize[size_int];
        memcpy(serialize, (const void*)&epoch,size_int);
        //print_text(serialize, size_int);
        element_s sig_v = bls.bls_sign(sk_v,serialize,sizeof(serialize));
        
        return make_pair(make_pair(vk_v, sig_e), sig_v);
    }
    pair<pair<int,int>,pair<pair<element_s,element_s>,element_s>> DGSA_issuance_v(pair<pair<element_s,element_s>,element_s> cred, int V, int epoch, vector<element_s> pk_i){
        vector<element_s> message;
        element_s v_id, epoch_s;
        element_init_Zr(&v_id, &ps_i.params.pairing);
        element_init_Zr(&epoch_s, &ps_i.params.pairing);
        element_set_si(&v_id, V);
        element_set_si(&epoch_s, epoch);
        //print_text(serialize2, size_int2);
        //auto serialized1 = to_bytes(V); auto serialized2 = to_bytes(epoch);
        message.push_back(v_id);
        message.push_back(epoch_s);
        if(ps_i.ps_verify(pk_i,message, cred)){
            cout<<"credential recieved from issuer"<<endl;
        }
        else{
            cout<<"abort"<<endl;exit(1);
        }
        return make_pair(make_pair(V,epoch),cred);
    }
    tuple<element_s,element_s,pair<element_s, pair<element_s, element_s>>> DGSA_auth(vector<element_s> pk_i,pair<pair<int,int>,pair<pair<element_s,element_s>,element_s>> c, tuple<int,int,pair<element_s, element_s>> message){
        char ans[1000];
        cout<<"This is DGSA auth"<<endl;
        element_s sigma_1_dash, sigma_2_dash,r, S_id, S_a_dash;
        element_init_G1(&sigma_1_dash, &ps_i.params.pairing);
        element_init_G1(&sigma_2_dash, &ps_i.params.pairing);
        element_init_Zr(&r, &ps_i.params.pairing);
        element_init_Zr(&S_id, &ps_i.params.pairing);
        element_init_Zr(&S_a_dash, &ps_i.params.pairing);
        element_random(&r);element_random(&S_id);element_random(&S_a_dash);
        element_printf("sigma_1 = %B\n\n",&c.second.first.second);
        
        element_printf("sigma_2 = %B\n\n",&c.second.second);
        element_pow_zn(&sigma_1_dash, &c.second.first.second, &r);
        element_pow_zn(&sigma_2_dash, &c.second.second, &r);
        element_printf("sigma_1_dash = %B\n\n",&sigma_1_dash);
        element_printf("sigma_2_dash = %B\n\n",&sigma_2_dash);
        element_s temp1, temp2;
        element_init_G1(&temp1, &ps_i.params.pairing);
        element_init_G1(&temp2, &ps_i.params.pairing);

        element_pow_zn(&temp1, &sigma_1_dash, &S_id);
        element_pow_zn(&temp2, &sigma_2_dash, &S_a_dash);
        element_printf("sigma_1_dash_mul_S_id = %B\n\n",&temp1);
        element_printf("sigma_2_dash_mul_S_a = %B\n\n",&temp2);
        // element_printf("temp1 = %B\n\n", &temp1);
        // element_printf("temp2 = %B\n\n", &temp2);
        element_s pai1,pai2, u;
        element_init_GT(&pai1,&ps_i.params.pairing);
        element_init_GT(&pai2,&ps_i.params.pairing);
        element_init_GT(&u,&ps_i.params.pairing);

        element_printf("pk[0] = %B\n\n",&pk_i[0]);
        element_printf("pk[1] = %B\n\n",&pk_i[1]);
        element_printf("pk[2] = %B\n\n",&pk_i[2]);
        element_printf("pk[3] = %B\n\n",&pk_i[3]);
        element_printf("pk[4] = %B\n\n",&pk_i[4]);
        pairing_apply(&pai1,&temp1,&pk_i[2], &ps_i.params.pairing);

        pairing_apply(&pai2,&temp2,&pk_i[pk_i.size()-1] ,&ps_i.params.pairing);

        element_mul(&u, &pai1, &pai2);
        element_printf("u = %B \n\n",&u);

        tuple<element_s,int, tuple<int,int,pair<element_s, element_s>>,element_s, element_s,vector<element_s>> challenge = make_tuple(u,c.first.second, message, sigma_1_dash, sigma_2_dash, pk_i);
       
        element_s challenge_hash;
        element_init_Zr(&challenge_hash, &ps_i.params.pairing);

        pair<byte*, int> serialize = convert_to_byte(challenge);
    //     std::cout << std::hex << std::setfill('0') ;
    // for( byte b : serialized ) std::cout << std::setw(2) << int(b) << ' ' ;
    // std::cout << '\n' ;
        element_from_hash(&challenge_hash, serialize.first, serialize.second);
        element_printf("hash = %B \n\n",&challenge_hash);
       // print_text(serialize.first,serialize.second);
        delete[] serialize.first;
        element_s temp3, temp4, temp5, temp6, id_s, epoch;
        element_init_Zr(&temp3, &ps_i.params.pairing);
        element_init_Zr(&temp4, &ps_i.params.pairing);
        element_init_Zr(&temp5, &ps_i.params.pairing);
        element_init_Zr(&temp6, &ps_i.params.pairing);
        element_init_Zr(&id_s, &ps_i.params.pairing);
        element_init_Zr(&epoch, &ps_i.params.pairing);
        element_set_si(&id_s, c.first.first);
        element_printf("s_id = %B\n\n",&S_id);
        element_printf("c = %B\n\n",&challenge_hash);
        element_printf("id = %B\n\n",&id_s);
        // element_snprint(ans,sizeof(ans),&id_s);
        // cout<<"id_s = "<<string(ans)<<endl;

        element_mul(&temp3,&challenge_hash, &id_s);
        element_printf("cid = %B\n\n",&temp3);
        element_mul(&temp4,&challenge_hash, &c.second.first.first);
        element_printf("m_dash = %B\n\n", &c.second.first.first);
        element_sub(&temp5, &S_id , &temp3);
        element_printf("result = %B\n\n",&temp5);
        element_sub(&temp6, &S_a_dash , &temp4);
        element_printf("result2 = %B\n\n",&temp6);
        pair<element_s, element_s> verify = make_pair(temp5, temp6);
        pair<element_s, pair<element_s, element_s>> pie = make_pair(challenge_hash, verify);

        
        // cout<<"A = "<<c.first.second<<endl;

        // element_printf("m_sig_1 = %B\n\n",&get<2>(message).first);
        // element_printf("m_sig_2 = %B\n\n",&get<2>(message).second);
        // element_printf("sig_1 = %B\n\n",&sigma_1_dash);
        // element_printf("sig_2 = %B\n\n",&sigma_2_dash);
        // cout<<"Public key while signing"<<endl;
        // for(auto i = pk_i.begin();i!=pk_i.end();i++){
        //     element_printf("%B\n\n",i);
        // }
        return make_tuple(sigma_1_dash, sigma_2_dash, pie);
    }
    bool DGSA_verify(vector<element_s> pk_i, tuple<int,int,pair<element_s, element_s>> message, int epoch, tuple<element_s,element_s,pair<element_s, pair<element_s, element_s>>> tok){
         cout<<"This is DGSA verify"<<endl;
         element_s temp1,temp2,temp3,temp4;
         element_init_G1(&temp1, &ps_i.params.pairing);
         element_init_G1(&temp2, &ps_i.params.pairing);
         element_init_G1(&temp3, &ps_i.params.pairing);
         element_init_G1(&temp4, &ps_i.params.pairing);

         element_pow_zn(&temp1, &get<0>(tok), &get<2>(tok).second.first);
         element_pow_zn(&temp2, &get<0>(tok), &get<2>(tok).second.second);
         element_pow_zn(&temp3, &get<1>(tok), &get<2>(tok).first);
         element_pow_zn(&temp4, &get<0>(tok), &get<2>(tok).first);


         element_printf("result = %B\n\n",&get<2>(tok).second.first);
         element_printf("result2 = %B\n\n",&get<2>(tok).second.second);
         element_printf("hash = %B\n\n",&get<2>(tok).first);
         element_printf("sigma_1 = %B\n\n",&get<0>(tok));
         element_printf("sigma_2 = %B\n\n",&get<1>(tok));
         element_s inv_X, inv_ep, temp5, temp6, epoch_s, neg_epoch, neg_one;
         element_init_G2(&inv_X, &ps_i.params.pairing);
         element_init_G2(&inv_ep, &ps_i.params.pairing);
         element_init_G2(&temp5, &ps_i.params.pairing);
         element_init_G2(&temp6, &ps_i.params.pairing);
         element_init_Zr(&epoch_s, &ps_i.params.pairing);
         element_init_Zr(&neg_epoch, &ps_i.params.pairing);
         element_init_Zr(&neg_one, &ps_i.params.pairing);
         element_set_si(&epoch_s, epoch);
         element_set_si(&neg_one, -1);
         element_printf("neg_one = %B\n\n",&neg_one);

         
         //char ans[1000];

        // element_snprint(ans,sizeof(ans),&epoch_s);
        cout<<"epoch = "<<epoch<<endl;
            element_neg(&neg_epoch, &epoch_s);
            element_printf("neg_epoch = %B\n\n",&neg_epoch);
        //  element_pow_zn(&temp5, &pk_i[3], &neg_epoch);
        element_pow_zn(&inv_X, &pk_i[1], &neg_one);
         //element_invert(&inv_X, &pk_i[1]);
         //element_invert(&inv_ep, &pk_i[3]);
        element_pow_zn(&temp5, &pk_i[3], &neg_epoch);
        element_mul(&temp6, &inv_X, &temp5);
        
        element_s pai1,pai2,pai3,pai4,u, temp7;
        element_init_GT(&pai1,&ps_i.params.pairing);
        element_init_GT(&pai2,&ps_i.params.pairing);
        element_init_GT(&pai3,&ps_i.params.pairing);
        element_init_GT(&pai4,&ps_i.params.pairing);
        element_init_GT(&temp7,&ps_i.params.pairing);
        element_init_GT(&u,&ps_i.params.pairing);

        pairing_apply(&pai1,&temp1,&pk_i[2], &ps_i.params.pairing);

        pairing_apply(&pai2,&temp2,&pk_i[pk_i.size()-1] ,&ps_i.params.pairing);
        pairing_apply(&pai3,&temp3,&pk_i[0] ,&ps_i.params.pairing);
        pairing_apply(&pai4,&temp4,&temp6 ,&ps_i.params.pairing);

        element_mul(&temp7, &pai1, &pai2);
        element_mul(&temp7, &temp7, &pai3);
        element_mul(&u, &temp7, &pai4);

        
        tuple<element_s,int, tuple<int,int,pair<element_s, element_s>>,element_s, element_s,vector<element_s>> challenge = make_tuple(u,epoch, message, get<0>(tok), get<1>(tok), pk_i);
        // element_snprint(ans,sizeof(ans),&u);
        // cout<<"u_v = "<<string(ans)<<endl;
        
        element_s challenge_hash;
        element_init_Zr(&challenge_hash, &ps_i.params.pairing);
        pair<byte*, int> serialize = convert_to_byte(challenge);
       // print_text(serialize.first,serialize.second);
    //     std::cout << std::hex << std::setfill('0') ;
    // for( byte b : serialized ) std::cout << std::setw(2) << int(b) << ' ' ;
    // std::cout << '\n' ;
        element_from_hash(&challenge_hash, serialize.first, serialize.second);
        delete [] serialize.first;
        element_printf("u = %B \n\n",&u);
        // cout<<"A = "<<epoch<<endl;
        // element_printf("m_sig_1 = %B\n\n",&get<2>(message).first);
        // element_printf("m_sig_2 = %B\n\n",&get<2>(message).second);
        // element_printf("sig_1 = %B\n\n",&get<0>(tok));
        // element_printf("sig_2 = %B\n\n",&get<1>(tok));
        // cout<<"Public key while verifying"<<endl;
        // for(auto i = pk_i.begin();i!=pk_i.end();i++){
        //     element_printf("%B\n\n",i);
        // }
        // element_snprint(ans,sizeof(ans),&challenge_hash);
        // cout<<"x = "<<string(ans)<<endl;
        // element_snprint(ans,sizeof(ans),&get<2>(tok).first);
        // cout<<"y = "<<string(ans)<<endl;
        return element_cmp(&challenge_hash, &get<2>(tok).first);
    }
    tuple<int, int, pair<element_s,element_s>, tuple<element_s,element_s,pair<element_s, pair<element_s, element_s>>>> Enter_request(pair<pair<int,int>,pair<pair<element_s,element_s>,element_s>> cred_v,vector<element_s> pk_i, int zone_num, int time){
        int flag =true;
        for(auto i = Lk.begin(); i!= Lk.end();i++){
            if(Lk.find(make_pair(zone_num,time)) !=Lk.end()){
                flag = false;
                break;
            }
        }
        if(flag){
        cout<<"creating new credential"<<endl;

        tuple<int, int, pair<element_s, element_s>> z_t_ek = make_tuple(zone_num,time,make_pair(pke_public,pke_public));
        
        tuple<element_s,element_s,pair<element_s, pair<element_s, element_s>>> tok_v = DGSA_auth(pk_i,cred_v,z_t_ek);

        return make_tuple(zone_num, time, make_pair(pke_public,pke_public), tok_v);
        }
    }
    tuple<int, int, pair<element_s,element_s>, tuple<element_s,element_s,pair<element_s, pair<element_s, element_s>>>> Enter_responder(pair<pair<int,int>,pair<pair<element_s,element_s>,element_s>> cred_w,vector<element_s> pk_i, int zone_num, int time, tuple<int, int, pair<element_s, element_s>, tuple<element_s,element_s,pair<element_s, pair<element_s, element_s>>>> key_broadcast_msg){
        tuple<int, int, pair<element_s, element_s>> z_t_ek = make_tuple(zone_num,time,get<2>(key_broadcast_msg));
        if(DGSA_verify(pk_i,z_t_ek, 11, get<3>(key_broadcast_msg))){   // TO DO function which generates epoch using time value
            
            cout<<"DGSA verified"<<endl;
            
            element_s key_z_t;
            element_init_GT(&key_z_t, &pke_v.params.pairing);
            pair<unsigned char *, int> buf = Lk.at(make_pair(zone_num,time));
            //print_text(buf.first,buf.second);
            char ans[1000];
            
            element_from_hash(&key_z_t, buf.first, buf.second);
            
            int si;
            si = element_length_in_bytes(&key_z_t);
            cout<<si<<endl;
            unsigned char ex[si];
            element_to_bytes(ex, &key_z_t);
            cout<<"above this"<<endl;
            //print_text(ex,si);
            int result = 0;
            for (int i = 0; i < si; i++) {
                result <<= 8;
                result |= ex[i];
            }
            point_to_key[result] = buf;
            // element_snprint(ans,sizeof(ans),&key_z_t);
            // cout<<"key_z_t = "<<string(ans)<<endl;

        //     element_snprint(ans,sizeof(ans),&get<2>(key_broadcast_msg).second);
        //     cout<<"public key = "<<string(ans)<<endl;
        //    element_snprint(ans,sizeof(ans),&get<2>(key_broadcast_msg).first);
        //     cout<<"priv_key = "<<string(ans)<<endl;


            pair<element_s, element_s> cipher = pke_v.pke_enc(get<2>(key_broadcast_msg).second, key_z_t);
            
            tuple<element_s,element_s,pair<element_s, pair<element_s, element_s>>> tok_w = DGSA_auth(pk_i,cred_w, make_tuple(zone_num, time, cipher));
            // cout<<"reach"<<endl;
            return make_tuple(zone_num, time, cipher, tok_w);
        }
        // else{
        //     cout<<"unauthorized vehicle!"<<endl;
            
        //     return 
        // }

    }
    void Zone_key_extraction(tuple<int, int, pair<element_s,element_s>, tuple<element_s,element_s,pair<element_s, pair<element_s, element_s>>>>  enc_key_and_msg, vector<element_s> pk_i){
        if(DGSA_verify(pk_i,make_tuple(get<0>(enc_key_and_msg),get<1>(enc_key_and_msg),get<2>(enc_key_and_msg)), 11, get<3>(enc_key_and_msg))){
           char ans[1000];
           
           element_s K_z_t = pke_v.pke_dec(pke_private, get<2>(enc_key_and_msg));
        //     element_snprint(ans,sizeof(ans),&pke_public);
        //     cout<<"publ = "<<string(ans)<<endl;
        //    element_snprint(ans,sizeof(ans),&pke_private);
        //     cout<<"priv_key = "<<string(ans)<<endl;
           element_s r;
           element_init_GT(&r, &pke_v.params.pairing);
           
        //    element_snprint(ans,sizeof(ans),&K_z_t);
        //     cout<<"key_z_t = "<<string(ans)<<endl;
           
           int si;
           si = element_length_in_bytes(&K_z_t);
           unsigned char buf[si];
           element_to_bytes(buf, &K_z_t);
           
           uint64_t result = 0;
            for (int i = 0; i < si; i++) {
                result <<= 8;
                result |= buf[i];
            }
           pair<unsigned char*, int> key = point_to_key[result];
           //print_text(buf,si);
           Lk[make_pair(get<0>(enc_key_and_msg),get<1>(enc_key_and_msg))] = key;
           return;
        }
        // else{
        //     cout<<"received response from an unauthorized vehicle!"<<endl;
        //     return;
        // }
    }
    void Zone_key_generation(int zone_num, int time){
           AutoSeededRandomPool prng;
	       static byte Kp[AES::DEFAULT_KEYLENGTH];
	       prng.GenerateBlock(Kp, sizeof(Kp));
           //print_text(Kp,AES::DEFAULT_KEYLENGTH);
           Lk[make_pair(zone_num, time)] = make_pair(Kp, 16);
    }
    void Exit_zone(int zone_num, int time){
        Lk.erase(make_pair(zone_num, time));
    }

    void send_payload(string payload, unordered_set<pair<int,int>> Y){


    }
    void receive_payload(){

    }
};

pair<pair<element_s,element_s>,element_s> Long_term_cred(Enrollment_authority *e, Vehicle *v, int vehicle_id){
    pair<int,element_s> s = v->enroll(e->pk_e, vehicle_id);

    element_s sig_e = e->enroll_vehicle(s.first,s.second);
    //element_printf("this is sig_e = %B\n",&sig_e);

    pair<pair<element_s,element_s>,element_s> cert_v = v->generate_cert(sig_e);

    return cert_v;

}

pair<pair<int,int>,pair<pair<element_s,element_s>,element_s>> Short_term_cred(Enrollment_authority *e, Issuer *i, Vehicle *v,pair<pair<element_s,element_s>,element_s> long_term_cred, int vehicle_id, int epoch){
    pair<pair<element_s,element_s>,element_s> data = v->gen_cred_for_authorization(long_term_cred, epoch);

    if(i->check_vehicle_cred(data,vehicle_id,epoch,v->bls,e->pk_e)){
        cout<<"Vehicle long term credential valid !"<<endl;
    }
    else{
        cout<<"Invalid long term credential!"<<endl;
    }

    pair<pair<element_s,element_s>,element_s> ans = i->DGSA_issuance_i(vehicle_id,epoch);
    pair<pair<int,int>,pair<pair<element_s,element_s>,element_s>> CRED = v->DGSA_issuance_v(ans,vehicle_id,epoch,i->pk_i);
    return CRED;
}
void Enter_vehicle(Issuer* i, Vehicle* v,pair<pair<int,int>,pair<pair<element_s,element_s>,element_s>>short_crd_v, Vehicle* w,pair<pair<int,int>,pair<pair<element_s,element_s>,element_s>> short_crd_w, int zone_num, int time){
    tuple<int, int, pair<element_s,element_s>, tuple<element_s,element_s,pair<element_s, pair<element_s, element_s>>>> broadcast_msg = v->Enter_request(short_crd_v,i->pk_i,zone_num,time);

    tuple<int, int, pair<element_s,element_s>, tuple<element_s,element_s,pair<element_s, pair<element_s, element_s>>>> send_to_v = w->Enter_responder(short_crd_w, i->pk_i,zone_num, time, broadcast_msg);

    // v->Zone_key_extraction(send_to_v,i->pk_i);

}
int main(){

    Enrollment_authority e;
    e.key_gen_e();
    Issuer i(e.bls);
    i.key_gen_i();
    PKE pk;
    Vehicle v(e.bls,i.ps, pk);
    Vehicle w(e.bls, i.ps, pk);
    
    int id, epoch, id2;
    cin>>id>>epoch >>id2;
    clock_t start_time = clock();
    pair<pair<element_s,element_s>,element_s> cred_v = Long_term_cred(&e,&v,10);
    char ans[1000];
    element_snprint(ans,sizeof(ans),&cred_v.second);
    //cout<<"cred_v = "<<string(ans)<<endl;

    clock_t end_time = clock();
    double time_taken = double(end_time - start_time) / CLOCKS_PER_SEC;
    //cout<<"Time take for long term credential = "<< time_taken<<endl;
    start_time = clock();
    pair<pair<int,int>,pair<pair<element_s,element_s>,element_s>> short_cred_v = Short_term_cred(&e,&i,&v, cred_v, 10,11);
    end_time = clock();
    element_snprint(ans,sizeof(ans),&short_cred_v.second.first.first);
    //cout<<"a = "<<string(ans)<<endl;
    element_snprint(ans,sizeof(ans),&short_cred_v.second.first.second);
    //cout<<"sigma_1 = "<<string(ans)<<endl;
    element_snprint(ans,sizeof(ans),&short_cred_v.second.second);
    //cout<<"sigma_2 = "<<string(ans)<<endl;
    time_taken = double(end_time - start_time) / CLOCKS_PER_SEC;
    //cout<<"Time take for short term credential = "<< time_taken<<endl;
    pair<pair<element_s,element_s>,element_s> cred_w = Long_term_cred(&e,&w,20);
    pair<pair<int,int>,pair<pair<element_s,element_s>,element_s>> short_cred_w = Short_term_cred(&e,&i,&w, cred_w, 20,11);
    w.Zone_key_generation(100,20);

    start_time = clock();
    Enter_vehicle(&i,&v,short_cred_v, &w, short_cred_w, 100, 20);
    // end_time = clock();
    // time_taken = double(end_time - start_time) / CLOCKS_PER_SEC;
    // cout<<"Time take for getting the zonal keys = "<< time_taken<<endl;
    








    // SE sk;
    // byte key = sk.key_gen();

    // string ans("This is a string");
    // byte serial[ans.size()];
    // memcpy(serial,ans.data(),ans.size());
    // cout<<ans.size()<<endl;
    // print_text(serial, ans.size());
    // pair<ByteQueue, byte> cipher = sk.Enc(&key, 16, serial, ans.size());
    // HexEncoder encoder(new FileSink(cout));
    // cout << "Cipher text: ";
    // cipher.first.CopyTo(encoder);
    // encoder.MessageEnd();
    // cout << endl;
    
    
    





    // element_s r;
    // element_init_Zr(&r, &i.ps.params.pairing);
    // element_random(&r);
    // tuple<element_s,element_s,pair<element_s, pair<element_s, element_s>>> fgj = v.DGSA_auth(i.pk_i,CRED,make_tuple(43,56,make_pair(r,r)));
    // bool s1 = v.DGSA_verify(i.pk_i,make_tuple(43,56,make_pair(r,r)),15,fgj);
    // PS a;
    // pair<vector<element_s>,vector<element_s>> ans = a.ps_key_gen(1);
    // vector<unsigned char *> message;
    // vector<int> size;
    // int V = 10;
    // int epoch = 809;
    // auto serialized1 = to_bytes(V); auto serialized2 = to_bytes(epoch);
    // message.push_back(serialized1.begin());size.push_back(serialized1.size());
    // message.push_back(serialized2.begin());size.push_back(serialized2.size());
    // pair<pair<element_s,element_s>,element_s> sign = a.ps_sign(ans.second,message,size);
    // a.ps_verify(ans.first, message,size, sign);
    // Vehicle W(e.bls,i.ps);
    // pair<int,element_s> s2 = W.enroll(e.pk_e, 11);

    // element_s sig_e2 = e.enroll_vehicle(s2.first,s2.second);

    // pair<pair<element_s,element_s>,element_s> cert_w = W.generate_cert(sig_e2);

    // pair<pair<element_s,element_s>,element_s> data2 = W.gen_cred_for_authorization(cert_w, 20);

    // if(i.check_vehicle_cred(data2,11,20,W.bls,e.pk_e)){
    //     cout<<"yess"<<endl;
    // }
    // else{
    //     cout<<"noo"<<endl;
    // }

    // pair<pair<element_s,element_s>,element_s> ans2 = i.DGSA_issuance_i(11,20);
    // pair<pair<int,int>,pair<pair<element_s,element_s>,element_s>> CRED2 = W.DGSA_issuance_v(ans2,11,20,i.pk_i);
    // element_s r2;
    // element_init_Zr(&r2, &i.ps.params.pairing);
    // element_random(&r);
    // tuple<element_s,element_s,pair<element_s, pair<element_s, element_s>>> fgj = v.DGSA_auth(i.pk_i,CRED,make_tuple(43,56,make_pair(r,r)));
    // bool s1 = v.DGSA_verify(i.pk_i,make_tuple(43,56,make_pair(r,r)),15,fgj);

    return 0;
}