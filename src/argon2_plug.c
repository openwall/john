/*
 * Argon2 source code package
 *
 * Written by Daniel Dinu and Dmitry Khovratovich, 2015
 *
 * This work is licensed under a Creative Commons CC0 1.0 License/Waiver.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along
 * with
 * this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 * modified by Agnieszka Bielec <bielecagnieszka8 at gmail.com>
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "argon2.h"
#include "argon2_encoding.h"
#include "argon2_core.h"

int argon2_ctx(argon2_context *context, argon2_type type) {
    /* 1. Validate all inputs */
    int result = argon2_validate_inputs(context);
    uint32_t memory_blocks, segment_length;
    argon2_instance_t instance;

    if (ARGON2_OK != result) {
        return result;
    }

    if (Argon2_d != type && Argon2_i != type) {
        return ARGON2_INCORRECT_TYPE;
    }

    /* 2. Align memory size */
    /* Minimum memory_blocks = 8L blocks, where L is the number of lanes */
    memory_blocks = context->m_cost;

    if (memory_blocks < 2 * ARGON2_SYNC_POINTS * context->lanes) {
        memory_blocks = 2 * ARGON2_SYNC_POINTS * context->lanes;
    }

    segment_length = memory_blocks / (context->lanes * ARGON2_SYNC_POINTS);
    /* Ensure that all segments have equal length */
    memory_blocks = segment_length * (context->lanes * ARGON2_SYNC_POINTS);

    instance.version = context->version;
    instance.memory = context->memory;
    instance.passes = context->t_cost;
    instance.memory_blocks = memory_blocks;
    instance.segment_length = segment_length;
    instance.lane_length = segment_length * ARGON2_SYNC_POINTS;
    instance.lanes = context->lanes;
    instance.threads = context->threads;
    instance.type = type;
    instance.memory = context->memory;
    instance.pseudo_rands = context->pseudo_rands;

    /* 3. Initialization: Hashing inputs, allocating memory, filling first
     * blocks
     */
    result = argon2_initialize(&instance, context);

    if (ARGON2_OK != result) {
        return result;
    }

    /* 4. Filling memory */
    result = argon2_fill_memory_blocks(&instance);

    if (ARGON2_OK != result) {
        return result;
    }
    /* 5. Finalization */
    argon2_finalize(context, &instance);

    return ARGON2_OK;
}

int argon2_hash(const uint32_t t_cost, const uint32_t m_cost,
                const uint32_t parallelism, const void *pwd,
                const size_t pwdlen, const void *salt, const size_t saltlen,
                void *hash, const size_t hashlen, char *encoded,
                const size_t encodedlen, argon2_type type,
                const uint32_t version, void *memory, void *pseudo_rands){

    argon2_context context;
    int result;
    //uint8_t *out;

    if (hashlen > ARGON2_MAX_OUTLEN) {
        return ARGON2_OUTPUT_TOO_LONG;
    }

    if (hashlen < ARGON2_MIN_OUTLEN) {
        return ARGON2_OUTPUT_TOO_SHORT;
    }

    context.out = (uint8_t *)hash;
    context.outlen = (uint32_t)hashlen;
    context.pwd = CONST_CAST(uint8_t *)pwd;
    context.pwdlen = (uint32_t)pwdlen;
    context.salt = CONST_CAST(uint8_t *)salt;
    context.saltlen = (uint32_t)saltlen;
    context.secret = NULL;
    context.secretlen = 0;
    context.ad = NULL;
    context.adlen = 0;
    context.t_cost = t_cost;
    context.m_cost = m_cost;
    context.lanes = parallelism;
    context.threads = parallelism;
    context.flags = ARGON2_DEFAULT_FLAGS;
    context.version = version;
    context.memory = memory;
    context.pseudo_rands=pseudo_rands;

    result = argon2_ctx(&context, type);

    if (result != ARGON2_OK) {
        //free(out);
        return result;
    }

    /* if encoding requested, write it */
    if (encoded && encodedlen) {
        if (argon2_encode_string(encoded, encodedlen, &context, type) != ARGON2_OK) {
            //free(out);
            return ARGON2_ENCODING_FAIL;
        }
    }

    return ARGON2_OK;
}


int argon2d_ctx(argon2_context *context) {
    return argon2_ctx(context, Argon2_d);
}

int argon2i_ctx(argon2_context *context) {
    return argon2_ctx(context, Argon2_i);
}

int argon2_verify_ctx(argon2_context *context, const char *hash,
                      argon2_type type) {
    int result;
    if (0 == context->outlen || NULL == hash) {
        return ARGON2_OUT_PTR_MISMATCH;
    }

    result = argon2_ctx(context, type);

    if (ARGON2_OK != result) {
        return result;
    }

    return 0 == memcmp(hash, context->out, context->outlen);
}

int argon2d_verify_ctx(argon2_context *context, const char *hash) {
    return argon2_verify_ctx(context, hash, Argon2_d);
}

int argon2i_verify_ctx(argon2_context *context, const char *hash) {
    return argon2_verify_ctx(context, hash, Argon2_i);
}

const char *argon2_error_message(int error_code) {
    switch (error_code) {
    case ARGON2_OK:
        return "OK";
    case ARGON2_OUTPUT_PTR_NULL:
        return "Output pointer is NULL";
    case ARGON2_OUTPUT_TOO_SHORT:
        return "Output is too short";
    case ARGON2_OUTPUT_TOO_LONG:
        return "Output is too long";
    case ARGON2_PWD_TOO_SHORT:
        return "Password is too short";
    case ARGON2_PWD_TOO_LONG:
        return "Password is too long";
    case ARGON2_SALT_TOO_SHORT:
        return "Salt is too short";
    case ARGON2_SALT_TOO_LONG:
        return "Salt is too long";
    case ARGON2_AD_TOO_SHORT:
        return "Associated data is too short";
    case ARGON2_AD_TOO_LONG:
        return "Associated data is too long";
    case ARGON2_SECRET_TOO_SHORT:
        return "Secret is too short";
    case ARGON2_SECRET_TOO_LONG:
        return "Secret is too long";
    case ARGON2_TIME_TOO_SMALL:
        return "Time cost is too small";
    case ARGON2_TIME_TOO_LARGE:
        return "Time cost is too large";
    case ARGON2_MEMORY_TOO_LITTLE:
        return "Memory cost is too small";
    case ARGON2_MEMORY_TOO_MUCH:
        return "Memory cost is too large";
    case ARGON2_LANES_TOO_FEW:
        return "Too few lanes";
    case ARGON2_LANES_TOO_MANY:
        return "Too many lanes";
    case ARGON2_PWD_PTR_MISMATCH:
        return "Password pointer is NULL, but password length is not 0";
    case ARGON2_SALT_PTR_MISMATCH:
        return "Salt pointer is NULL, but salt length is not 0";
    case ARGON2_SECRET_PTR_MISMATCH:
        return "Secret pointer is NULL, but secret length is not 0";
    case ARGON2_AD_PTR_MISMATCH:
        return "Associated data pointer is NULL, but ad length is not 0";
    case ARGON2_MEMORY_ALLOCATION_ERROR:
        return "Memory allocation error";
    case ARGON2_FREE_MEMORY_CBK_NULL:
        return "The free memory callback is NULL";
    case ARGON2_ALLOCATE_MEMORY_CBK_NULL:
        return "The allocate memory callback is NULL";
    case ARGON2_INCORRECT_PARAMETER:
        return "Argon2_Context context is NULL";
    case ARGON2_INCORRECT_TYPE:
        return "There is no such version of Argon2";
    case ARGON2_OUT_PTR_MISMATCH:
        return "Output pointer mismatch";
    case ARGON2_THREADS_TOO_FEW:
        return "Not enough threads";
    case ARGON2_THREADS_TOO_MANY:
        return "Too many threads";
    case ARGON2_MISSING_ARGS:
        return "Missing arguments";
    case ARGON2_ENCODING_FAIL:
        return "Encoding failed";
    case ARGON2_DECODING_FAIL:
        return "Decoding failed";
    case ARGON2_THREAD_FAIL:
        return "Threading failure";
    case ARGON2_DECODING_LENGTH_FAIL:
        return "Some of encoded parameters are too long or too short";
    case ARGON2_VERIFY_MISMATCH:
        return "The password does not match the supplied hash";
    default:
        return "Unknown error code";
    }
}

size_t argon2_encodedlen(uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
                         uint32_t saltlen, uint32_t hashlen) {
    return strlen("$argon2x$v=$m=,t=,p=$$") + argon2_numlen(t_cost) + argon2_numlen(m_cost)
        + argon2_numlen(parallelism) + argon2_b64len(saltlen) + argon2_b64len(hashlen)
        + argon2_numlen(ARGON2_VERSION_NUMBER);
}
