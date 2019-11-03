#include <sodium.h>

/* kx vector generation.
   gcc -o vectors vectors.c -lsodium */

int main (void) {
  char alice_pk[crypto_kx_PUBLICKEYBYTES] = {0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,
                                             0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,
                                             0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,
                                             0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a};

  char alice_sk[crypto_kx_SECRETKEYBYTES] = {0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,
                                             0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
                                             0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,
                                             0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a};

  char bob_pk[crypto_kx_PUBLICKEYBYTES] = {0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,
                                           0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
                                           0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,
                                           0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f};

  char bob_sk[crypto_kx_SECRETKEYBYTES] = {0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
                                           0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
                                           0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
                                           0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb};

  char alice_rx[crypto_kx_SESSIONKEYBYTES];
  char alice_tx[crypto_kx_SESSIONKEYBYTES];

  char bob_rx[crypto_kx_SESSIONKEYBYTES];
  char bob_tx[crypto_kx_SESSIONKEYBYTES];

  char           hex[65];
  int ret;

  ret = sodium_init();

  printf("initial parameters:\n");

  sodium_bin2hex(hex, sizeof hex, alice_pk, crypto_kx_PUBLICKEYBYTES);
  printf("\talice_pk: \t%s\n", hex);
  sodium_bin2hex(hex, sizeof hex, alice_sk, crypto_kx_SECRETKEYBYTES);
  printf("\talice_sk: \t%s\n", hex);

  sodium_bin2hex(hex, sizeof hex, bob_pk, crypto_kx_PUBLICKEYBYTES);
  printf("\tbob_pk: \t%s\n", hex);
  sodium_bin2hex(hex, sizeof hex, bob_sk, crypto_kx_PUBLICKEYBYTES);
  printf("\tbob_sk: \t%s\n\n", hex);

  printf("calculating client session keys:\n");

  ret = crypto_kx_client_session_keys(alice_rx, alice_tx, alice_pk, alice_sk, bob_pk);

  sodium_bin2hex(hex, sizeof hex, alice_rx, crypto_kx_SESSIONKEYBYTES);
  printf("\talice_rx: \t%s\n", hex);
  sodium_bin2hex(hex, sizeof hex, alice_tx, crypto_kx_SESSIONKEYBYTES);
  printf("\talice_tx: \t%s\n", hex);

  ret = crypto_kx_client_session_keys(bob_rx, bob_tx, bob_pk, bob_sk, alice_pk);

  sodium_bin2hex(hex, sizeof hex, bob_rx, crypto_kx_SESSIONKEYBYTES);
  printf("\tbob_rx: \t%s\n", hex);
  sodium_bin2hex(hex, sizeof hex, bob_tx, crypto_kx_SESSIONKEYBYTES);
  printf("\tbob_tx: \t%s\n\n", hex);

  printf("calculating server session keys:\n");

  ret = crypto_kx_server_session_keys(alice_rx, alice_tx, alice_pk, alice_sk, bob_pk);

  sodium_bin2hex(hex, sizeof hex, alice_rx, crypto_kx_SESSIONKEYBYTES);
  printf("\talice_rx: \t%s\n", hex);
  sodium_bin2hex(hex, sizeof hex, alice_tx, crypto_kx_SESSIONKEYBYTES);
  printf("\talice_tx: \t%s\n", hex);

  ret = crypto_kx_server_session_keys(bob_rx, bob_tx, bob_pk, bob_sk, alice_pk);

  sodium_bin2hex(hex, sizeof hex, bob_rx, crypto_kx_SESSIONKEYBYTES);
  printf("\tbob_rx: \t%s\n", hex);
  sodium_bin2hex(hex, sizeof hex, bob_tx, crypto_kx_SESSIONKEYBYTES);
  printf("\tbob_tx: \t%s\n", hex);

  return 0;
}
