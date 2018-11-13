cmake_minimum_required(VERSION 3.1 FATAL_ERROR)

configure_file(test.conf      test.conf      COPYONLY)
configure_file(test.crt.pem   test.crt.pem   COPYONLY)
configure_file(test.key.pem   test.key.pem   COPYONLY)
configure_file(router.crt.pem router.crt.pem COPYONLY)
