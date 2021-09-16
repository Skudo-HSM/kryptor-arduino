/**************************************************
 *                                                *
 *      Skudo Oš HSM - Arduino interface library  *
 *                                                *
 *          Version 1.0 September 2021            *
 *              Copyright Skudo Oš                *
 *                www.skudo.tech                  *
 **************************************************/

#pragma once

#if defined(__cplusplus)
extern "C" {
#endif

void assert_cs();
void deassert_cs();

void send_request(const unsigned char* buf, size_t size);
void complete_request(const unsigned char* buf, size_t size);
void read_reply(unsigned char* buf, size_t size);

#if defined(__cplusplus)
}
#endif
