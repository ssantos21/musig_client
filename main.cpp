#include "cli/CLI11.hpp"
#include "crypto/sha256sum.h"
#include "fmt/core.h"
#include "nlohmann/json.hpp"
#include "utils/include_secp256k1_zkp_lib.h"
#include "utils/strencodings.h"

#include <cpr/cpr.h>
#include <iostream>
#include <openssl/rand.h>

using json = nlohmann::json;

bool create_keypair(secp256k1_keypair &keypair) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char seckey[32];

    while (1) {
        if (RAND_bytes(seckey, sizeof(seckey)) != 1) {
            return false;
        }

        if (secp256k1_ec_seckey_verify(ctx, seckey)) {
            break;
        }
    }
    
    int return_val = secp256k1_keypair_create(ctx, &keypair, seckey);

    secp256k1_context_destroy(ctx);
    
    return return_val;
}

bool extract_keys_from_keypair(
    const secp256k1_context *ctx,
    const secp256k1_keypair &keypair,
    unsigned char seckey[32], 
    secp256k1_pubkey& pubkey, 
    unsigned char compressed_pubkey[33], 
    int compressed_pubkey_size,
    std::string& error_message) {

    if (!secp256k1_keypair_sec(ctx, seckey, &keypair)) {
        error_message = "Failed to get the secret key from the key pair.";
        return false;
    }

    if (!secp256k1_keypair_pub(ctx, &pubkey, &keypair)) {
        error_message = "Failed to get the public key from the key pair.";
        return false;
    }

    // Serialize pubkey2 in a compressed form (33 bytes)
    size_t len = compressed_pubkey_size;
    int return_val = secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED);
    assert(return_val);
    // Should be the same size as the size of the output, because we passed a 33 byte array.
    if (len != compressed_pubkey_size) {
        error_message = "The serialized public key must be a 33-byte array.";
        return false;
    }

    return true;
}

bool verify_aggregate_pubkey(
    const secp256k1_context* ctx,
    const secp256k1_pubkey& client_pubkey,
    const secp256k1_pubkey& server_pubkey,
    const secp256k1_xonly_pubkey& server_aggregate_xonly_pubkey,
    secp256k1_musig_keyagg_cache& cache
) {
    const secp256k1_pubkey *pubkeys_ptr[2];
    secp256k1_xonly_pubkey client_aggregate_xonly_pubkey;

    pubkeys_ptr[0] = &client_pubkey;
    pubkeys_ptr[1] = &server_pubkey;

    if (!secp256k1_musig_pubkey_agg(ctx, NULL, &client_aggregate_xonly_pubkey, &cache, pubkeys_ptr, 2)) {
        return false;
    }

    return secp256k1_xonly_pubkey_cmp(ctx, &client_aggregate_xonly_pubkey, &server_aggregate_xonly_pubkey) == 0;
}

bool create_aggregate_key(
    const secp256k1_keypair &keypair, 
    secp256k1_musig_keyagg_cache& cache,
    secp256k1_xonly_pubkey& aggregate_xonly_pubkey, 
    json& res_err) {

    unsigned char seckey[32];
    secp256k1_pubkey pubkey;
    unsigned char compressed_pubkey[33];

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    std::string error_message;
    bool return_val = extract_keys_from_keypair(
        ctx, keypair, seckey, pubkey, compressed_pubkey, sizeof(compressed_pubkey), error_message
    );

    if (!return_val) {
        res_err = {
            {"error_code", 1},
            {"error_message", error_message}
        };

        secp256k1_context_destroy(ctx);
        return false;
    }

    auto pubkey_str = key_to_string(compressed_pubkey, sizeof(compressed_pubkey));

    json params = {{ "pubkey", pubkey_str }};

    cpr::Response r = cpr::Post(cpr::Url{"http://0.0.0.0:18080/key_aggregation"}, cpr::Body{params.dump()});

    if (r.status_code == 200 && r.header["content-type"] == "application/json") {

        auto res_json = json::parse(r.text);

        assert(res_json["aggregated_pubkey"].is_string());
        std::string agg_pubkey_str = res_json["aggregated_pubkey"];

        // Check if the string starts with 0x and remove it if necessary
        if (agg_pubkey_str.substr(0, 2) == "0x") {
            agg_pubkey_str = agg_pubkey_str.substr(2);
        }

        std::vector<unsigned char> agg_pubkey_serialized = ParseHex(agg_pubkey_str);

        if (!secp256k1_xonly_pubkey_parse(ctx, &aggregate_xonly_pubkey, agg_pubkey_serialized.data())) {
            res_err = {
                {"error_code", 1},
                {"error_message", "Failed to parse aggregate public key."}
            };

            secp256k1_context_destroy(ctx);
            return false;
        }

        assert(res_json["server_pubkey"].is_string());
        std::string server_pubkey_str = res_json["server_pubkey"];

        // Check if the string starts with 0x and remove it if necessary
        if (server_pubkey_str.substr(0, 2) == "0x") {
            server_pubkey_str = server_pubkey_str.substr(2);
        }

        std::vector<unsigned char> server_pubkey_serialized = ParseHex(server_pubkey_str);

        // unsigned char pub_key_serialized[65];
        secp256k1_pubkey server_pubkey;

        // Deserialize the public key
        if (!secp256k1_ec_pubkey_parse(ctx, &server_pubkey, server_pubkey_serialized.data(), server_pubkey_serialized.size())) {
            res_err = {
                {"error_code", 1},
                {"error_message", "Failed to parse server public key."}
            };
            secp256k1_context_destroy(ctx);
            return false;
        }

        bool result = verify_aggregate_pubkey(ctx, pubkey, server_pubkey, aggregate_xonly_pubkey, cache);

        secp256k1_context_destroy(ctx);
        return result;
    } else {
        res_err = {
            {"error_code", r.status_code},
            {"error_message", r.text}
        };
        secp256k1_context_destroy(ctx);
        return false;
    }
}

bool generate_public_nonce(
    const secp256k1_context *ctx,
    const unsigned char seckey[32], 
    const secp256k1_pubkey& pubkey,
    const unsigned char *msg32, 
    secp256k1_musig_pubnonce& pubnonce,
    secp256k1_musig_secnonce& secnonce,
    std::string& error_message
) {

    unsigned char session_id[32];

    if (RAND_bytes(session_id, sizeof(session_id)) != 1) {
        error_message = "Failed to generate a random number for the session id!";
        return false;
    }

    if (!secp256k1_musig_nonce_gen(ctx, &secnonce, &pubnonce, session_id, seckey, &pubkey, msg32, NULL, NULL)) {
        error_message = "Failed to initialize session and create the nonces!";
        return false;
    }

    return true;
}

int test1()
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    

    secp256k1_keypair keypair;

    if (!create_keypair(keypair)) {
        std::cerr << "Failed to generate a random number for the private key." << std::endl;
        exit(1);
    }

    unsigned char seckey[32];

    if (!secp256k1_keypair_sec(ctx, seckey, &keypair)) {
        std::cerr <<  "Failed to get the secret key from the key pair." << std::endl;
        return 1;
    }

    std::string seckey_hex = key_to_string(seckey, sizeof(seckey));

    std::cout <<  "seckey: " << seckey_hex << std::endl;

    std::string message_hash;

    if (!get_sha256("execute_complete_scheme test", message_hash)) {
        std::cerr << "Failed to hash the message!" << std::endl;
        exit(1);
    }

    std::cout <<  "message_hash: " << message_hash << std::endl;

    secp256k1_context_destroy(ctx);

    return 0;
}

bool secp256k1_musig_pubnonce_to_hex(
    const secp256k1_context *ctx,
    const secp256k1_musig_pubnonce pubnonce,
    std::string& result
) {
    unsigned char pubnonce_serialized[66];
    if (!secp256k1_musig_pubnonce_serialize(ctx, pubnonce_serialized, &pubnonce)) {
        return false;
    }
    
    result = key_to_string(pubnonce_serialized, sizeof(pubnonce_serialized));

    return true;

}

bool hex_to_secp256k1_musig_pubnonce(
    const secp256k1_context *ctx,
    std::string pubnonce_hex, 
    secp256k1_musig_pubnonce& pubnonce
) {
    if (pubnonce_hex.substr(0, 2) == "0x") {
        pubnonce_hex = pubnonce_hex.substr(2);
    }

    std::vector<unsigned char> pubnonce_serialized = ParseHex(pubnonce_hex);

    assert(pubnonce_serialized.size() == 66);

    return secp256k1_musig_pubnonce_parse(ctx, &pubnonce, pubnonce_serialized.data());
}

bool get_server_partial_sign(
    const std::string& aggregate_pubkey_str, 
    const std::string& message_hash, 
    const secp256k1_musig_pubnonce& client_pubnonce,
    secp256k1_musig_pubnonce& server_pubnonce,
    secp256k1_musig_partial_sig& server_partial_sig,
    json& res_err
) {

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    std::string client_pubnonce_hex;

    if (!secp256k1_musig_pubnonce_to_hex(ctx, client_pubnonce, client_pubnonce_hex)) {
        std::cerr << "Error: Failed to serialize the client's public nonce" << std::endl;
        exit(1);
    }

    json params = {{ "aggregated_pubkey", aggregate_pubkey_str }, { "message_hash", message_hash }, {"pubnonce", client_pubnonce_hex}};

    cpr::Response r = cpr::Post(cpr::Url{"http://0.0.0.0:18080/partial_signature"}, cpr::Body{params.dump()});

    if (r.status_code == 200 && r.header["content-type"] == "application/json") {

        auto res_json = json::parse(r.text);
        assert(res_json["public_nonce"].is_string());
        assert(res_json["partial_sig"].is_string());
        std::string server_public_nonce_hex = res_json["public_nonce"];
        std::string serialized_partial_sig_hex = res_json["partial_sig"];

        if (!hex_to_secp256k1_musig_pubnonce(ctx, server_public_nonce_hex, server_pubnonce)) {
            res_err = {
                {"error_code", 1},
                {"error_message", "Failed to parse the server's public nonce. Invalid public nonce."}
            };
            secp256k1_context_destroy(ctx);
            return false;
        }

        // Check if the string starts with 0x and remove it if necessary
        if (serialized_partial_sig_hex.substr(0, 2) == "0x") {
            serialized_partial_sig_hex = serialized_partial_sig_hex.substr(2);
        }

        if (serialized_partial_sig_hex.size() != 64) {
            std::cerr << "Invalid server's partial signature length. Must be 32 bytes!" << std::endl;
            exit(1);
        }

        unsigned char serialized_partial_sig[32];
        if (!hex_to_bytes(serialized_partial_sig_hex, serialized_partial_sig)) {
            res_err = {
                {"error_code", 1},
                {"error_message", "Failed to parse the server's partial signature bytes."}
            };
            secp256k1_context_destroy(ctx);
            return false;
        }

        if (!secp256k1_musig_partial_sig_parse(ctx, &server_partial_sig, serialized_partial_sig)) {
            res_err = {
                {"error_code", 1},
                {"error_message", "Failed to parse the server's partial signature. Invalid partial signature."}
            };
            secp256k1_context_destroy(ctx);
            return false;
        }

        secp256k1_context_destroy(ctx);
        return true;

    } else {
        res_err = {
            {"error_code", r.status_code},
            {"error_message", r.text}
        };
        secp256k1_context_destroy(ctx);
        return false;
    }
}

bool create_partial_sign(
    const secp256k1_context *ctx,
    const secp256k1_keypair& keypair, 
    const unsigned char *msg32,
    secp256k1_musig_secnonce& local_secnonce,
    const secp256k1_musig_pubnonce& local_pubnonce,
    const secp256k1_musig_pubnonce& remote_pubnonce,
    const secp256k1_musig_keyagg_cache& cache,
    secp256k1_musig_session& session,
    secp256k1_musig_partial_sig& partial_sig,
    std::string& error_message
) {
    secp256k1_musig_aggnonce agg_pubnonce;

    const secp256k1_musig_pubnonce *pubnonces[2];
    pubnonces[0] = &remote_pubnonce;
    pubnonces[1] = &local_pubnonce;

    secp256k1_pubkey pubkey;
    if (!secp256k1_keypair_pub(ctx, &pubkey, &keypair)) {
        error_message = "Failed to get the public key from the key pair.";
        return false;
    }

    if (!secp256k1_musig_nonce_agg(ctx, &agg_pubnonce, pubnonces, 2)) {
        error_message = "Failed to create aggregate nonce!";
        return false;
    }

    if (!secp256k1_musig_nonce_process(ctx, &session, &agg_pubnonce, msg32, &cache, NULL)) {
        error_message = "Failed to initialize the session!";
        return false;
    }

    if (!secp256k1_musig_partial_sign(ctx, &partial_sig, &local_secnonce, &keypair, &cache, &session)) {
        error_message = "Failed to produce a partial signature!";
        return false;
    }

    if (!secp256k1_musig_partial_sig_verify(ctx, &partial_sig, &local_pubnonce, &pubkey, &cache, &session)) {
        error_message = "Failed to verify the partial signature!";
        return false;
    }

    return true;
}

void execute_complete_scheme() {

    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey aggregate_xonly_pubkey;
    secp256k1_musig_keyagg_cache cache;
    json res_err;

     if (!create_keypair(keypair)) {
        std::cerr << "Failed to generate a random number for the private key." << std::endl;
        exit(1);
    }

    bool result = create_aggregate_key(keypair, cache, aggregate_xonly_pubkey, res_err);

    if (!result) {
        std::cerr << res_err << std::endl;
        exit(1);
    }

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    unsigned char compressed_aggregate_pubkey[32];

    /* Serialize pubkey2 in a compressed form (33 bytes) */
    size_t len = sizeof(compressed_aggregate_pubkey);
    bool return_val = secp256k1_xonly_pubkey_serialize(ctx, compressed_aggregate_pubkey, &aggregate_xonly_pubkey);
    assert(return_val);
    /* Should be the same size as the size of the output, because we passed a 33 byte array. */
    assert(len == sizeof(compressed_aggregate_pubkey));

    auto aggregate_pubkey_hex = key_to_string(compressed_aggregate_pubkey, sizeof(compressed_aggregate_pubkey));

    std::string message_hash;
    unsigned char msg[32];

    if (!get_sha256("execute_complete_scheme test", message_hash)) {
        std::cerr << "Failed to hash the message!" << std::endl;
        exit(1);
    } 

    if (message_hash.size() != 64) {
        std::cerr << "Invalid message hash length. Must be 32 bytes!" << std::endl;
        exit(1);
    }

    if (!hex_to_bytes(message_hash, msg)) {
        std::cerr << "Invalid message hash!" << std::endl;
        exit(1);
    }

    std::string error_message;

    unsigned char seckey[32];
    secp256k1_pubkey pubkey;
    unsigned char compressed_pubkey[33];

    return_val = extract_keys_from_keypair(
        ctx, keypair, seckey, pubkey, compressed_pubkey, sizeof(compressed_pubkey), error_message
    );

    if (!return_val) {
        std::cerr << "Error: " << error_message << std::endl;
        exit(1);
    }

    secp256k1_musig_pubnonce client_pubnonce;
    secp256k1_musig_secnonce client_secnonce;

    return_val = generate_public_nonce(
        ctx, seckey, pubkey, msg, client_pubnonce, client_secnonce, error_message
    );

    secp256k1_musig_pubnonce server_pubnonce;
    secp256k1_musig_partial_sig server_partial_sig;

    get_server_partial_sign(aggregate_pubkey_hex, message_hash, client_pubnonce, server_pubnonce, server_partial_sig, res_err);

    secp256k1_musig_session session;
    secp256k1_musig_partial_sig client_partial_sig;
    return_val = create_partial_sign(ctx,
        keypair, 
        msg,
        client_secnonce,
        client_pubnonce,
        server_pubnonce,
        cache,
        session,
        client_partial_sig,
        error_message
    );

    if (!return_val) {
        std::cerr << "Error: " << error_message << std::endl;
        exit(1);
    }

    const secp256k1_musig_partial_sig *partial_sigs[2];

    partial_sigs[0] = &client_partial_sig;
    partial_sigs[1] = &server_partial_sig;

    unsigned char sig[64];
    secp256k1_musig_partial_sig_agg(ctx, sig, &session, partial_sigs, 2);

    if (!secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &aggregate_xonly_pubkey)) {
        std::cerr << "Invalid signature." << std::endl;
        exit(1);
    } else {
        std::cout << "Signature validated successfully." << std::endl;
    }

    secp256k1_context_destroy(ctx);

    // --

    auto sig_hex = key_to_string(sig, sizeof(sig));
    
    json res = {{ "aggregated_pubkey_hex", aggregate_pubkey_hex }, { "aggregated_signature", sig_hex }};

    std::cout << res << std::endl;
}

void execute_test_sqlite3() {

    std::cout << "test sqlite3" << std::endl;
}

const std::string COMM_EXECUTE_COMPLETE_SCHEME = "execute-complete-scheme";
const std::string COMM_TEST_SQLITE3 = "test-sqlite3";

int main(int argc, char **argv)
{
    CLI::App app{"MuSig2 client"};
    app.set_version_flag("--version", std::string("0.0.1"));
    CLI::App *execute_complete_scheme_comm = app.add_subcommand(COMM_EXECUTE_COMPLETE_SCHEME, "Run the complete MuSig2 client-server process for development and testing purposes.");
    CLI::App *execute_test_sqlite3 = app.add_subcommand(COMM_TEST_SQLITE3, "Test sqlite3.");
    
    app.require_subcommand();
    CLI11_PARSE(app, argc, argv);

    if (app.get_subcommands().size() > 1) {
        std::cerr << "Only one command is allowed" << std::endl;
        return 1;
    }

    CLI::App *subcom = app.get_subcommands().at(0);

    if (subcom == execute_complete_scheme_comm) {
        execute_complete_scheme();
    } else if (subcom == execute_test_sqlite3) {

    } else {
        std::cerr << "Unknown command" << std::endl;
        return 1;
    }

    // return test1();
    return 0;
}