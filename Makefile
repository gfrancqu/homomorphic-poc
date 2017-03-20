####################################################
 # 
 # File Name 		:Makefile
 # Created by		:Guillaume Francqueville
 # Creation date	:mars 14th, 2017
 # Last changed by 	:Guillaume Francqueville
 # Last change 		:mars 14th, 2017 12:03
 # Description		:Makefile poc crypto homomorphe
 #
####################################################

#### DEFAULT TARGETS ####
all:
	g++ -std=c++11 -lgmp -lboost_serialization -lshe -Llibshe/build/ -Wl,-rpath=libshe/build/ -Ilibshe/include/ -o poc client.cpp


clean:
	rm poc
