/****************************************************
 * 
 * File Name 		:client.cpp
 * Created by		:Guillaume Francqueville
 * Creation date	:mars 14th, 2017
 * Last changed by 	:Guillaume Francqueville
 * Last change 		:mars 14th, 2017 12:03
 * Description		:POC chiffrement homomorphe, client
 *
****************************************************/


#include "she.hpp"

using she::ParameterSet;
using she::PrivateKey;
using she::CompressedCiphertext;
using she::EncryptedArray;
using std::vector;
using she::sum;

int main(int argc, char **argv)
{
  /*
   * declaration des variables 
   */
  const ParameterSet params = ParameterSet::generate_parameter_set(62, 1, 42);

  //genere la clé privée
  const PrivateKey privateK(params) ;

  // plaintext 
  const vector<bool> plaintext1 = {1, 0, 1, 0, 1, 0, 1, 0};
  const vector<bool> plaintext2 = {0, 1, 1, 1, 0, 0, 1, 1};

  // resultats attendus
  const vector<bool> expectedXOR =   {1, 1, 0, 1, 1, 0, 0, 1};
  const vector<bool> expectedAND =   {0, 0, 1, 0, 0, 0 ,1 ,0};

  //chiffres les plaintext
  const CompressedCiphertext c1 = privateK.encrypt(plaintext1);
  const CompressedCiphertext c2 = privateK.encrypt(plaintext2);

  EncryptedArray serv1;
  EncryptedArray serv2;

  printf("[+] Client side \n");
  printf("plaintext1 : %x%x%x%x%x%x%x%x \n",plaintext1[0],plaintext1[1],plaintext1[2],plaintext1[3],plaintext1[4],plaintext1[5],plaintext1[6],plaintext1[7]);
  printf("plaintext2 : %x%x%x%x%x%x%x%x \n",plaintext2[0],plaintext2[1],plaintext2[2],plaintext2[3],plaintext2[4],plaintext2[5],plaintext2[6],plaintext2[7]);
  printf("expectedxor: %x%x%x%x%x%x%x%x \n",expectedXOR[0],expectedXOR[1],expectedXOR[2],expectedXOR[3],expectedXOR[4],expectedXOR[5],expectedXOR[6],expectedXOR[7]);
  printf("expectedand: %x%x%x%x%x%x%x%x \n",expectedAND[0],expectedAND[1],expectedAND[2],expectedAND[3],expectedAND[4],expectedAND[5],expectedAND[6],expectedAND[7]);
  
  

  //server side
  printf("\n[+] SERVERSIDE \n");
  serv1 = c1.expand();
  serv2 = c2.expand();
  
  printf("[+] received cipher1 : %x%x%x%x%x%x%x%x\n",serv1.elements()[0].get_ui(),serv1.elements()[1].get_ui(),serv1.elements()[2].get_ui(),serv1.elements()[3].get_ui(),serv1.elements()[4].get_ui(),serv1.elements()[5].get_ui(),serv1.elements()[6].get_ui(),serv1.elements()[7].get_ui());
  printf("[+] received cipher2 : %x%x%x%x%x%x%x%x\n",serv2.elements()[0].get_ui(),serv2.elements()[1].get_ui(),serv2.elements()[2].get_ui(),serv2.elements()[3].get_ui(),serv2.elements()[4].get_ui(),serv2.elements()[5].get_ui(),serv2.elements()[6].get_ui(),serv2.elements()[7].get_ui());

  
  EncryptedArray xored = serv1 ^ serv2 ;
  EncryptedArray anded = serv1 & serv2 ;

    
  vector<bool> xordecrypted = privateK.decrypt(xored);
  vector<bool> anddecrypted = privateK.decrypt(anded);
  
  printf("[+] assert xordecrypted== expectedxor ?");
  fflush(stdout);
  assert(expectedXOR == xordecrypted);

  printf(" OK\n[+] assert anddecrypted == expectedand ?");
  fflush(stdout);
  assert(expectedAND == anddecrypted);
  printf("OK\n");
}
