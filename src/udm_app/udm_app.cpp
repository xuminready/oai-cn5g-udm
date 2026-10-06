/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "udm_app.hpp"

#include <unistd.h>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/date_time/posix_time/time_formatters.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <regex>
#include <set>

#include "3gpp_29.500.h"
#include "3gpp_29.503.h"
#include "PatchItem.h"
#include "ProblemDetails.h"
#include "SequenceNumber.h"
#include "SqnScheme.h"
#include "SqnScheme_anyOf.h"
#include "authentication_algorithms_with_5gaka.hpp"
#include "conversions.hpp"
#include "http_client.hpp"
#include "logger.hpp"
#include "output_wrapper.hpp"
#include "sha256.hpp"
#include "MonitoringReport.h"
#include "udm.h"
#include "udm_config.hpp"
#include "udm_nrf.hpp"
#include "udm_sbi_helper.hpp"

using namespace oai::_3gpp::model;
using namespace oai::utils;
using namespace oai::udm::app;
using namespace oai::udm::config;
using namespace std::chrono;
using namespace boost::placeholders;
using namespace oai::udm::api;

extern udm_app* udm_app_inst;
extern udm_config udm_cfg;
udm_nrf* udm_nrf_inst = nullptr;
extern std::shared_ptr<oai::http::http_client> http_client_inst;

//------------------------------------------------------------------------------
udm_app::udm_app(const std::string& config_file, udm_event& ev)
    : event_sub(ev), m_mutex_hplmn(), m_mutex_udm_event_subscriptions() {
  udm_event_subscriptions        = {};
  udm_event_subscriptions_per_ue = {};
  hplmn                          = {};
  m_udm_instance_id = to_string(boost::uuids::random_generator()());
}

//------------------------------------------------------------------------------
udm_app::~udm_app() {
  // Disconnect the boost connection
  if (loss_of_connectivity_connection.connected())
    loss_of_connectivity_connection.disconnect();
  if (ue_reachability_for_data_connection.connected())
    ue_reachability_for_data_connection.disconnect();

  if (udm_nrf_inst) {
    delete udm_nrf_inst;
    udm_nrf_inst = nullptr;
  }
  Logger::udm_app().debug("Delete UDM APP instance...");
}

//------------------------------------------------------------------------------
bool udm_app::start() {
  Logger::udm_app().startup("Starting...");

  // Register to NRF
  if (udm_cfg.register_nrf) {
    try {
      udm_nrf_inst = new udm_nrf(event_sub);
      udm_nrf_inst->register_to_nrf();
      Logger::udm_app().info("NRF TASK Created ");
    } catch (std::exception& e) {
      Logger::udm_app().error("Cannot create NRF TASK: %s", e.what());
      return false;
    }
  }

  // Subscribe to UE Loss of Connectivity Status signal
  loss_of_connectivity_connection = event_sub.subscribe_loss_of_connectivity(
      boost::bind(&udm_app::handle_ee_loss_of_connectivity, this, _1, _2, _3));
  ue_reachability_for_data_connection =
      event_sub.subscribe_ue_reachability_for_data(boost::bind(
          &udm_app::handle_ee_ue_reachability_for_data, this, _1, _2, _3));

  Logger::udm_app().startup("Started");
  return true;
}

//------------------------------------------------------------------------------
void udm_app::stop() {
  // Deregister to NRF
  if (udm_cfg.register_nrf) {
    if (udm_nrf_inst) {
      udm_nrf_inst->deregister_to_nrf();
    }
  }
}

//------------------------------------------------------------------------------
void udm_app::handle_generate_auth_data_request(
    const std::string& supiOrSuci,
    const oai::_3gpp::model::AuthenticationInfoRequest&
        authenticationInfoRequest,
    nlohmann::json& auth_info_response, uint32_t& code) {
  Logger::udm_ueau().info("Handle Generate Auth Data Request");

  uint8_t rand[16] = {0};
  uint8_t opc[16]  = {0};
  uint8_t key[16]  = {0};
  uint8_t sqn[6]   = {0};
  uint8_t amf[2]   = {0};

  uint8_t* r_sqn        = nullptr;  // for resync
  std::string r_sqnms_s = {};       // for resync
  uint8_t r_rand[16]    = {0};      // for resync
  uint8_t r_auts[14]    = {0};      // for resync

  uint8_t mac_a[8]     = {0};
  uint8_t ck[16]       = {0};
  uint8_t ik[16]       = {0};
  uint8_t ak[6]        = {0};
  uint8_t xres[16]     = {0};
  uint8_t xres_len     = 8;
  uint8_t xresStar[16] = {0};
  uint8_t autn[16]     = {0};
  uint8_t kausf[32]    = {0};

  std::string rand_s         = {};
  std::string autn_s         = {};
  std::string xresStar_s     = {};
  std::string kausf_s        = {};
  std::string sqn_s          = {};
  std::string amf_s          = {};
  std::string key_s          = {};
  std::string opc_s          = {};
  std::string algorithm_id_s = "milenage";

  std::string snn        = authenticationInfoRequest.getServingNetworkName();
  std::string supi       = {};
  std::string remote_uri = {};
  std::string msg_body   = {};
  nlohmann::json problem_details_json = {};
  ProblemDetails problem_details      = {};

  if (supiOrSuci.find("imsi-") == 0) {
    Logger::udm_ueau().debug("5GS mobile identity type: SUPI");
    if ((supiOrSuci.length() < (6 + 5)) || (supiOrSuci.length() > (6 + 15))) {
      std::string error = "Invalid IMSI length";
      problem_details.setCause("USER_NOT_FOUND");
      problem_details.setStatus(oai::common::sbi::http_status_code::NOT_FOUND);
      problem_details.setDetail("User " + supiOrSuci + " " + error);
      to_json(problem_details_json, problem_details);

      Logger::udm_ueau().warn("User " + supiOrSuci + " " + error);
      auth_info_response = problem_details_json;
      code               = oai::common::sbi::http_status_code::NOT_FOUND;
      return;
    }
    // No change, format is already IMSI
    supi = supiOrSuci;
  } else if (supiOrSuci.find("suci-") == 0) {
    Logger::udm_ueau().debug("5GS mobile identity type: SUCI");
    std::string error            = {};
    std::string routingIndicator = {};
    if (!Authentication_5gaka::suciSidf(
            udm_cfg.subscriber_profiles, supiOrSuci, routingIndicator, supi,
            error)) {
      problem_details.setCause("USER_NOT_FOUND");
      problem_details.setStatus(oai::common::sbi::http_status_code::NOT_FOUND);
      problem_details.setDetail("User " + supiOrSuci + " " + error);
      to_json(problem_details_json, problem_details);

      Logger::udm_ueau().warn("User " + supiOrSuci + " " + error);
      auth_info_response = problem_details_json;
      code               = oai::common::sbi::http_status_code::NOT_FOUND;
      return;
    }
    Logger::udm_ueau().debug("SUPI %s ", supi);
  }

  // Validate SNN
  oai::_3gpp::model::PlmnId plmn_id = {};
  if (!validate_snn(snn, plmn_id)) {
    Logger::udm_ueau().info("SNN is not valid");
    code = oai::common::sbi::http_status_code::NOT_ACCEPTABLE;
    std::string problem_description =
        "SNN is not valid for this UE (SUPI " + supi + ")";
    set_problem_details(
        code, udm_protocol_application_error::CONTEXT_NOT_FOUND,
        problem_description, auth_info_response);
    Logger::udm_ueau().warn(problem_description);
    return;
  }
  Logger::udm_ueau().debug(
      "SUPI %s, SNN %s, PLMN Id (MCC %s, MNC %s)", supi, snn, plmn_id.getMcc(),
      plmn_id.getMnc());

  // Store PLMN info to be used later
  store_plmn_id(supi, plmn_id);

  // Get authentication related info
  remote_uri = udm_sbi_helper::get_udr_authentication_subscription_uri(supi);
  Logger::udm_ueau().debug("Remote URI: " + remote_uri);

  oai::http::request http_request =
      http_client_inst->prepare_json_request(remote_uri);
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::GET, http_request);

  nlohmann::json response_data = {};
  try {
    response_data = nlohmann::json::parse(http_response.body);
  } catch (nlohmann::json::exception& e) {  // error handling
    Logger::udm_ueau().info("Could not get JSON content from UDR response");
    code = oai::common::sbi::http_status_code::NOT_FOUND;
    std::string problem_description = "User " + supi + " not found";
    set_problem_details(
        code, udm_protocol_application_error::USER_NOT_FOUND,
        problem_description, auth_info_response);
    Logger::udm_ueau().warn(problem_description);

    return;
  }

  // Process the response
  std::string auth_method_s = response_data.at("authenticationMethod");
  if (!auth_method_s.compare("5G_AKA") ||
      !auth_method_s.compare("AuthenticationVector")) {
    try {
      key_s = response_data.at("encPermanentKey");
      conv::hex_str_to_uint8(key_s.c_str(), key);
      output_wrapper::print_buffer(
          "udm_ueau", "Result For F1-Alg Key", key, 16);

      opc_s = response_data.at("encOpcKey");
      conv::hex_str_to_uint8(opc_s.c_str(), opc);
      output_wrapper::print_buffer(
          "udm_ueau", "Result For F1-Alg OPC", opc, 16);

      amf_s = response_data.at("authenticationManagementField");
      conv::hex_str_to_uint8(amf_s.c_str(), amf);
      output_wrapper::print_buffer("udm_ueau", "Result For F1-Alg AMF", amf, 2);

      sqn_s = response_data["sequenceNumber"].at("sqn");
      conv::hex_str_to_uint8(sqn_s.c_str(), sqn);
      output_wrapper::print_buffer(
          "udm_ueau", "Result For F1-Alg SQN: ", sqn, 6);

      algorithm_id_s = response_data.at("algorithmId");
      output_wrapper::print_buffer(
          "udm_ueau", "Result For Algorithm ID: ",
          (const uint8_t*) algorithm_id_s.c_str(), algorithm_id_s.length());
    } catch (nlohmann::json::exception& e) {
      // error handling
      code = oai::common::sbi::http_status_code::FORBIDDEN;
      std::string problem_description =
          "Missing authentication parameters in UDR's response";
      set_problem_details(
          code, udm_protocol_application_error::AUTHENTICATION_REJECTED,
          problem_description, auth_info_response);
      Logger::udm_ueau().warn(problem_description);
      return;
    }
  } else {
    // error handling
    code = oai::common::sbi::http_status_code::NOT_IMPLEMENTED;
    std::string problem_description =
        "Non 5G_AKA authenticationMethod configuration available, method set "
        "= " +
        auth_method_s;
    set_problem_details(
        code, udm_protocol_application_error::UNSUPPORTED_PROTECTION_SCHEME,
        problem_description, auth_info_response);
    Logger::udm_ueau().warn(problem_description);
    return;
  }

  if (authenticationInfoRequest.resynchronizationInfoIsSet()) {
    // Resync procedure
    Logger::udm_ueau().info("Start Resynchronization procedure");
    ResynchronizationInfo resynchronization_info =
        authenticationInfoRequest.getResynchronizationInfo();
    std::string r_rand_s = resynchronization_info.getRand();
    std::string r_auts_s = resynchronization_info.getAuts();

    Logger::udm_ueau().info("[resync] r_rand = " + r_rand_s);
    Logger::udm_ueau().info("[resync] r_auts = " + r_auts_s);

    conv::hex_str_to_uint8(r_rand_s.c_str(), r_rand);
    conv::hex_str_to_uint8(r_auts_s.c_str(), r_auts);

    r_sqn = Authentication_5gaka::sqn_ms_derive(opc, key, r_auts, r_rand, amf);

    if (r_sqn) {  // Not NULL (validate auts)
      Logger::udm_ueau().info("Valid AUTS, generate new AV with SQNms");

      // Update SQN@UDR, replace SQNhe with SQNms
      remote_uri =
          udm_sbi_helper::get_udr_authentication_subscription_uri(supi);

      Logger::udm_ueau().debug("Remote URI: " + remote_uri);

      nlohmann::json sequence_number_json;
      SequenceNumber sequence_number;
      SqnScheme sqn_scheme_1;
      sqn_scheme_1.setEnumValue(
          SqnScheme_anyOf::eSqnScheme_anyOf::NON_TIME_BASED);
      sequence_number.setSqnScheme(sqn_scheme_1);
      r_sqnms_s = conv::uint8_to_hex_string(r_sqn, 6);
      sequence_number.setSqn(r_sqnms_s);
      std::map<std::string, int32_t> index;
      index["ausf"] = 0;
      sequence_number.setLastIndexes(index);
      to_json(sequence_number_json, sequence_number);

      Logger::udm_ueau().info(
          "Sequence Number %s", sequence_number_json.dump().c_str());

      nlohmann::json patch_item_json = {};
      PatchItem patch_item           = {};
      patch_item.setValue(sequence_number_json.dump());
      PatchOperation op;
      op.setEnumValue(PatchOperation_anyOf::ePatchOperation_anyOf::REPLACE);
      patch_item.setOp(op);
      patch_item.setFrom("");
      patch_item.setPath("");
      to_json(patch_item_json, patch_item);

      msg_body = "[" + patch_item_json.dump() + "]";
      Logger::udm_ueau().info(
          "Update UDR with PATCH message, body:  %s", msg_body.c_str());

      oai::http::request http_request =
          http_client_inst->prepare_json_request(remote_uri, msg_body);
      auto http_response = http_client_inst->send_http_request(
          oai::common::sbi::method_e::PATCH, http_request);

      // replace SQNhe with SQNms
      for (int i = 0; i < 6; i++)
        sqn[i] = r_sqn[i];  // generate first, increase later
      sqn_s = conv::uint8_to_hex_string(sqn, 16);
      // Logger::udm_ueau().debug("sqn string = "+sqn_s);
      sqn_s[12] = '\0';
      output_wrapper::print_buffer("udm_ueau", "SQNms", sqn, 6);

      if (r_sqn) {  // free
        free(r_sqn);
        r_sqn = NULL;
      }
    } else {
      Logger::udm_ueau().warn(
          "Invalid AUTS, generate new AV with SQNhe = " + sqn_s);
    }
  }

  // Increment SQN (to be used as current SQN)
  std::string current_sqn = {};
  increment_sqn(sqn_s, current_sqn);
  // Update SQN
  conv::hex_str_to_uint8(current_sqn.c_str(), sqn);
  Logger::udm_ueau().info("Current SQN %s", current_sqn.c_str());

  // 5GAKA functions
  Authentication_5gaka::generate_random(rand, 16);  // generate rand

  if (strncasecmp(algorithm_id_s.c_str(), "xor", 3) == 0) {
    Logger::udm_ueau().info("Using XOR/Dummy USIM authentication algorithm");
    uint8_t xdout[16];
    for (int i = 0; i < 16; i++) {
      xdout[i] = rand[i] ^ key[i];
    }

    // The length of XRES can vary based on the test SIM profile:
    // - 4 bytes (32 bits): old minimal test, R&S LTE R8 USIM.
    // - 8 bytes (64 bits): The most common length, Agilent Keysight Test SIM.
    // - 16 bytes (128 bits): The maximum allowed length, most secure. TS.48 v7
    if (strcasecmp(algorithm_id_s.c_str(), "xor4") == 0) {
      xres_len = 4;
    } else if (strcasecmp(algorithm_id_s.c_str(), "xor8") == 0) {
      xres_len = 8;
    } else {
      xres_len = 16;  // default to xor16 or xor
    }

    Logger::udm_ueau().info(
        "Using XRES length: %d bytes (algorithmId: %s)", xres_len,
        algorithm_id_s.c_str());
    memcpy(xres, xdout, xres_len);
    // CK is xdout rotated left by 1 byte
    for (int i = 0; i < 15; i++) {
      ck[i] = xdout[i + 1];
    }
    ck[15] = xdout[0];
    // IK is xdout rotated left by 2 bytes
    for (int i = 0; i < 14; i++) {
      ik[i] = xdout[i + 2];
    }
    ik[14] = xdout[0];
    ik[15] = xdout[1];
    // AK is xdout[3..8]
    memcpy(ak, xdout + 3, 6);

    // MAC_A is xdout[0..7] ^ (sqn || amf)
    uint8_t cdout[8];
    memcpy(cdout, sqn, 6);
    memcpy(cdout + 6, amf, 2);
    for (int i = 0; i < 8; i++) {
      mac_a[i] = xdout[i] ^ cdout[i];
    }
  } else {
    Logger::udm_ueau().info("Using Milenage authentication algorithm");
    Authentication_5gaka::f1(
        opc, key, rand, sqn, amf,
        mac_a);  // to compute mac_a
    Authentication_5gaka::f2345(
        opc, key, rand, xres, ck, ik,
        ak);  // to compute XRES, CK, IK, AK
    xres_len = 8;
  }

  Authentication_5gaka::generate_autn(
      sqn, ak, amf, mac_a,
      autn);  // generate AUTN
  Authentication_5gaka::annex_a_4_33501(
      ck, ik, xres, xres_len, rand, snn,
      xresStar);  // generate xres*
  Authentication_5gaka::derive_kausf(
      ck, ik, snn, sqn, ak,
      kausf);  // derive Kausf

  // convert uint8_t to string
  rand_s     = conv::uint8_to_hex_string(rand, 16);
  autn_s     = conv::uint8_to_hex_string(autn, 16);
  xresStar_s = conv::uint8_to_hex_string(xresStar, 16);
  kausf_s    = conv::uint8_to_hex_string(kausf, 32);

  // convert to json
  nlohmann::json AuthInfoResult                      = {};
  AuthInfoResult["authType"]                         = "5G_AKA";
  AuthInfoResult["authenticationVector"]["avType"]   = "5G_HE_AKA";
  AuthInfoResult["authenticationVector"]["rand"]     = rand_s;
  AuthInfoResult["authenticationVector"]["autn"]     = autn_s;
  AuthInfoResult["authenticationVector"]["xresStar"] = xresStar_s;
  AuthInfoResult["authenticationVector"]["kausf"]    = kausf_s;
  AuthInfoResult["supi"]                             = supi;

  // TODO: Separate into a new function
  // Do it after send ok to AUSF (to be verified)

  // Increment SQN (for the next round)
  std::string new_sqn = {};
  increment_sqn(current_sqn, new_sqn);
  Logger::udm_ueau().info("New SQN (for next round) = " + new_sqn);

  // Update SQN@UDR
  remote_uri = udm_sbi_helper::get_udr_authentication_subscription_uri(supi);

  Logger::udm_ueau().debug("Remote URI: " + remote_uri);

  nlohmann::json sequence_number_json;
  SequenceNumber sequence_number;
  SqnScheme sqn_scheme_2;
  sqn_scheme_2.setEnumValue(SqnScheme_anyOf::eSqnScheme_anyOf::NON_TIME_BASED);
  sequence_number.setSqnScheme(sqn_scheme_2);
  sequence_number.setSqn(new_sqn);
  std::map<std::string, int32_t> index;
  index["ausf"] = 0;
  sequence_number.setLastIndexes(index);
  to_json(sequence_number_json, sequence_number);

  nlohmann::json patch_item_json;
  PatchItem patch_item;
  patch_item.setValue(sequence_number_json.dump());
  PatchOperation op;
  op.setEnumValue(PatchOperation_anyOf::ePatchOperation_anyOf::REPLACE);
  patch_item.setOp(op);
  patch_item.setFrom("");
  patch_item.setPath("");
  to_json(patch_item_json, patch_item);

  msg_body = "[" + patch_item_json.dump() + "]";
  Logger::udm_ueau().info(
      "Update UDR with PATCH message, body:  %s", msg_body.c_str());

  http_request  = http_client_inst->prepare_json_request(remote_uri, msg_body);
  http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::PATCH, http_request);

  auth_info_response = AuthInfoResult;
  code               = oai::common::sbi::http_status_code::OK;
  Logger::udm_ueau().info("Send 200 OK response to AUSF");
  Logger::udm_ueau().info("AuthInfoResult %s", AuthInfoResult.dump().c_str());
  return;
}

//------------------------------------------------------------------------------
void udm_app::handle_confirm_auth(
    const std::string& supi, const oai::_3gpp::model::AuthEvent& authEvent,
    nlohmann::json& confirm_response, std::string& location, uint32_t& code) {
  std::string remote_uri              = {};
  std::string msg_body                = {};
  std::string auth_event_id           = {};
  nlohmann::json problem_details_json = {};
  ProblemDetails problem_details      = {};

  // Get user info
  remote_uri = udm_sbi_helper::get_udr_authentication_subscription_uri(supi);
  Logger::udm_ueau().debug("Remote URI: " + remote_uri);

  oai::http::request http_request =
      http_client_inst->prepare_json_request(remote_uri, msg_body);
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::GET, http_request);

  nlohmann::json response_data = {};
  try {
    response_data = nlohmann::json::parse(http_response.body.c_str());
  } catch (nlohmann::json::exception& e) {  // error handling
    Logger::udm_ueau().info("Could not get JSON content from UDR response");
    code = oai::common::sbi::http_status_code::NOT_FOUND;
    std::string problem_description = "User " + supi + " not found";
    set_problem_details(
        code, udm_protocol_application_error::USER_NOT_FOUND,
        problem_description, confirm_response);
    Logger::udm_ueau().warn(problem_description);
    return;
  }

  if (authEvent.isAuthRemovalInd()) {
    // error handling
    code = oai::common::sbi::http_status_code::BAD_REQUEST;
    std::string problem_description = "AuthRemovalInd should be set to false";
    set_problem_details(
        code, protocol_application_error::OPTIONAL_IE_INCORRECT,
        problem_description, confirm_response);
    Logger::udm_ueau().warn(problem_description);
    return;
  }

  // Update authentication status
  remote_uri = udm_sbi_helper::get_udr_authentication_status_uri(supi);
  Logger::udm_ueau().debug("Remote URI:" + remote_uri);

  nlohmann::json auth_event_json;
  to_json(auth_event_json, authEvent);

  msg_body = auth_event_json.dump();
  Logger::udm_ueau().debug("Request body = " + msg_body);

  http_request  = http_client_inst->prepare_json_request(remote_uri, msg_body);
  http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::PUT, http_request);

  std::string hash_value = sha256(supi + authEvent.getServingNetworkName());
  // Logger::udm_ueau().debug("\n\nauthEventId=" +
  // hash_value.substr(0,hash_value.length()/2));
  Logger::udm_ueau().debug("authEventId=" + hash_value);

  auth_event_id = hash_value;
  location      = udm_sbi_helper::get_auth_event_location(supi, auth_event_id);

  Logger::udm_ueau().info("Send 201 Created response to AUSF");
  confirm_response = auth_event_json;
  code             = oai::common::sbi::http_status_code::CREATED;
  return;
}

//------------------------------------------------------------------------------
void udm_app::handle_delete_auth(
    const std::string& supi, const std::string& authEventId,
    const oai::_3gpp::model::AuthEvent& authEvent,
    nlohmann::json& auth_response, uint32_t& code) {
  std::string remote_uri              = {};
  std::string msg_body                = {};
  nlohmann::json problem_details_json = {};
  ProblemDetails problem_details      = {};

  // Get user info
  remote_uri = udm_sbi_helper::get_udr_authentication_subscription_uri(supi);
  Logger::udm_ueau().debug("Remote URI:" + remote_uri);

  oai::http::request http_request =
      http_client_inst->prepare_json_request(remote_uri, msg_body);
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::GET, http_request);

  nlohmann::json response_data = {};
  try {
    response_data = nlohmann::json::parse(http_response.body.c_str());
  } catch (nlohmann::json::exception& e) {  // error handling
    Logger::udm_ueau().info("Could not get JSON content from UDR response");
    code = oai::common::sbi::http_status_code::NOT_FOUND;
    std::string problem_description = "User " + supi + " not found";
    set_problem_details(
        code, udm_protocol_application_error::USER_NOT_FOUND,
        problem_description, auth_response);
    Logger::udm_ueau().warn(problem_description);
    return;
  }

  if (!authEvent.isAuthRemovalInd()) {
    // error handling
    code = oai::common::sbi::http_status_code::BAD_REQUEST;
    std::string problem_description = "AuthRemovalInd should be set to true";
    set_problem_details(
        code, protocol_application_error::OPTIONAL_IE_INCORRECT,
        problem_description, auth_response);
    Logger::udm_ueau().warn(problem_description);
    return;
  }

  std::string hash_value = sha256(supi + authEvent.getServingNetworkName());
  // Logger::udm_ueau().debug("\n\nauthEventId=" +
  // hash_value.substr(0,hash_value.length()/2));
  Logger::udm_ueau().debug("authEventId=" + hash_value);

  if (!hash_value.compare(authEventId)) {
    // Delete authentication status
    remote_uri = udm_sbi_helper::get_udr_authentication_status_uri(supi);
    Logger::udm_ueau().debug("DELETE Request:" + remote_uri);

    nlohmann::json auth_event_json;
    to_json(auth_event_json, authEvent);

    oai::http::request http_request =
        http_client_inst->prepare_json_request(remote_uri, msg_body);
    auto http_response = http_client_inst->send_http_request(
        oai::common::sbi::method_e::DELETE, http_request);

    Logger::udm_ueau().info("Send 204 No_Content response to AUSF");
    auth_response = {};
    code          = oai::common::sbi::http_status_code::NO_CONTENT;
    return;
  } else {
    // error handling
    code = oai::common::sbi::http_status_code::NOT_FOUND;
    std::string problem_description = "Wrong authEventId";
    set_problem_details(
        code, udm_protocol_application_error::DATA_NOT_FOUND,
        problem_description, auth_response);
    Logger::udm_ueau().warn(problem_description);
    return;
  }
}

//------------------------------------------------------------------------------
void udm_app::handle_access_mobility_subscription_data_retrieval(
    const std::string& supi, nlohmann::json& response_data, uint32_t& code,
    PlmnId plmn_id) {
  // TODO: check if plmn_id available
  std::string remote_uri =
      udm_sbi_helper::get_udr_access_and_mobility_subscription_data_uri(
          supi, plmn_id);
  std::string body("");
  Logger::udm_sdm().debug("Remote URI: " + remote_uri);

  // Get response from UDR
  oai::http::request http_request =
      http_client_inst->prepare_json_request(remote_uri, body);
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::GET, http_request);

  try {
    Logger::udm_sdm().debug(
        "subscription-data: GET Response: " + http_response.body);
    response_data = nlohmann::json::parse(http_response.body.c_str());
  } catch (nlohmann::json::exception& e) {
    Logger::udm_sdm().info("Could not get JSON content from UDR response");
    code = oai::common::sbi::http_status_code::NOT_FOUND;
    std::string problem_description = "User " + supi + " not found";
    set_problem_details(
        code, udm_protocol_application_error::USER_NOT_FOUND,
        problem_description, response_data);
    Logger::udm_ueau().warn(problem_description);
    return;
  }
}

//------------------------------------------------------------------------------
void udm_app::handle_amf_registration_for_3gpp_access(
    const std::string& ue_id,
    const oai::_3gpp::model::Amf3GppAccessRegistration&
        amf_3gpp_access_registration,
    nlohmann::json& response_data, uint32_t& code) {
  std::string remote_uri              = {};
  nlohmann::json problem_details_json = {};
  ProblemDetails problem_details      = {};

  // Get 3gpp_registration related info
  remote_uri = udm_sbi_helper::get_udr_amf_3gpp_registration_uri(ue_id);
  Logger::udm_uecm().debug("Remote URI:" + remote_uri);

  nlohmann::json amf_registration_json;
  to_json(amf_registration_json, amf_3gpp_access_registration);

  // If this UE has active EE subscriptions, read the current registration
  // before updating it, to be able to compare the old and the new values
  // (e.g., to see whether the PEI or the serving PLMN has changed)
  bool ue_has_subs = false;
  {
    std::shared_lock lock(m_mutex_udm_event_subscriptions);
    auto it = udm_event_subscriptions_per_ue.find(ue_id);
    ue_has_subs =
        (it != udm_event_subscriptions_per_ue.end() && !it->second.empty());
  }

  nlohmann::json old_registration = {};
  bool has_old                    = false;
  if (ue_has_subs) {
    oai::http::request get_req =
        http_client_inst->prepare_json_request(remote_uri);
    auto get_resp = http_client_inst->send_http_request(
        oai::common::sbi::method_e::GET, get_req);
    if (get_resp.status_code == oai::common::sbi::http_status_code::OK) {
      try {
        old_registration = nlohmann::json::parse(get_resp.body);
        has_old = old_registration.is_object() && !old_registration.empty();
      } catch (nlohmann::json::exception&) {
        has_old = false;
      }
    }
  }

  // Update AMF registration in UDR
  oai::http::request http_request = http_client_inst->prepare_json_request(
      remote_uri, amf_registration_json.dump());
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::PUT, http_request);

  try {
    Logger::udm_uecm().debug("HTTP Response: " + http_response.body);
    response_data = nlohmann::json::parse(http_response.body.c_str());
  } catch (nlohmann::json::exception& e) {  // error handling
    Logger::udm_uecm().info("Could not get JSON content from UDR response");
    std::string problem_description = "User " + ue_id + " not found";
    set_problem_details(
        oai::common::sbi::http_status_code::NOT_FOUND,
        udm_protocol_application_error::USER_NOT_FOUND, problem_description,
        response_data);
    Logger::udm_ueau().warn(problem_description);
    return;
  }
  Logger::udm_uecm().debug("HTTP response code %d", http_response.status_code);

  response_data = amf_registration_json;
  code          = http_response.status_code;

  // Notify the events detected by the UDM itself to the active EE
  // subscriptions of this UE:
  //  - CHANGE_OF_SUPI_PEI_ASSOCIATION: only if the PEI has changed
  //  - ROAMING_STATUS: if the serving PLMN has changed, or at the very first
  //    registration since there is nothing to compare with
  //  - CN_TYPE_CHANGE: at each registration
  if (code == oai::common::sbi::http_status_code::CREATED ||
      code == oai::common::sbi::http_status_code::OK ||
      code == oai::common::sbi::http_status_code::NO_CONTENT) {
    auto plmn_of = [](const nlohmann::json& reg) -> std::string {
      if (reg.contains("guami") && reg["guami"].contains("plmnId")) {
        const auto& p = reg["guami"]["plmnId"];
        return p.value("mcc", std::string{}) + p.value("mnc", std::string{});
      }
      return std::string{};
    };
    std::string old_pei =
        has_old ? old_registration.value("pei", std::string{}) : std::string{};
    std::string new_pei  = amf_registration_json.value("pei", std::string{});
    std::string old_plmn = has_old ? plmn_of(old_registration) : std::string{};
    std::string new_plmn = plmn_of(amf_registration_json);

    std::set<EventType_anyOf::eEventType_anyOf> detected_events;
    if (has_old && !new_pei.empty() && old_pei != new_pei)
      detected_events.insert(
          EventType_anyOf::eEventType_anyOf::CHANGE_OF_SUPI_PEI_ASSOCIATION);
    if (!has_old || old_plmn != new_plmn)
      detected_events.insert(EventType_anyOf::eEventType_anyOf::ROAMING_STATUS);
    detected_events.insert(EventType_anyOf::eEventType_anyOf::CN_TYPE_CHANGE);

    std::vector<std::shared_ptr<CreatedEeSubscription>> subs;
    {
      std::shared_lock lock(m_mutex_udm_event_subscriptions);
      auto it = udm_event_subscriptions_per_ue.find(ue_id);
      if (it != udm_event_subscriptions_per_ue.end()) {
        for (auto sid : it->second) {
          auto s = udm_event_subscriptions.find(sid);
          if (s != udm_event_subscriptions.end() && s->second)
            subs.push_back(s->second);
        }
      }
    }

    // Timestamp of the reports, in RFC3339 (UTC) format
    std::time_t now = std::time(nullptr);
    char ts_buf[32] = {};
    std::strftime(
        ts_buf, sizeof(ts_buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&now));
    std::string timestamp(ts_buf);

    for (const auto& ces : subs) {
      EeSubscription es    = ces->getEeSubscription();
      std::string callback = es.getCallbackReference();
      if (callback.empty()) continue;
      std::vector<MonitoringReport> reports;
      for (const auto& kv : es.getMonitoringConfigurations()) {
        auto ev = kv.second.getEventType().getEnumValue();
        if (detected_events.count(ev) == 0) continue;
        MonitoringReport report;
        try {
          report.setReferenceId(std::stoi(kv.first));
        } catch (std::exception&) {
        }
        report.setEventType(kv.second.getEventType());
        report.setTimeStamp(timestamp);
        reports.push_back(report);
      }
      if (!reports.empty()) notify_event_occurrence(callback, reports);
    }

    // If the UE is now served by another AMF, the subscriptions relayed to
    // the previous AMF have to be created again on the new one
    std::string old_amf =
        has_old ? old_registration.value("amfInstanceId", std::string{}) :
                  std::string{};
    std::string new_amf =
        amf_registration_json.value("amfInstanceId", std::string{});
    if (has_old && !new_amf.empty() && old_amf != new_amf) {
      std::vector<evsub_id_t> ids;
      {
        std::shared_lock lock(m_mutex_udm_event_subscriptions);
        auto it = udm_event_subscriptions_per_ue.find(ue_id);
        if (it != udm_event_subscriptions_per_ue.end()) ids = it->second;
      }
      Logger::udm_ee().info(
          "AMF reselection for %s (%s -> %s): re-subscribing %zu EE sub(s)",
          ue_id.c_str(), old_amf.c_str(), new_amf.c_str(), ids.size());
      std::string ue_cpy = ue_id;
      for (auto sid : ids) {
        relay_subscribe_to_amf(sid, ue_cpy);
      }
    }
  }
  return;
}

//------------------------------------------------------------------------------
void udm_app::handle_session_management_subscription_data_retrieval(
    const std::string& supi, nlohmann::json& response_data, uint32_t& code,
    const std::optional<oai::_3gpp::model::Snssai>& snssai,
    const std::optional<std::string>& dnn,
    const std::optional<oai::_3gpp::model::PlmnId>& plmn_id_opt) {
  // TODO: If PLMN Id is not available, use the HPLMN instead
  std::optional<oai::_3gpp::model::PlmnId> plmn_id = plmn_id_opt;
  if (!plmn_id_opt.has_value()) {
    get_hplmn_id(supi, plmn_id);
  }

  // If couldn't get PLMN Id, then reply with USER_NOT_FOUND
  if (!plmn_id.has_value()) {
    Logger::udm_sdm().info("Could not get JSON content from UDR response");
    code = oai::common::sbi::http_status_code::NOT_FOUND;
    std::string problem_description = "User " + supi + " not found";
    set_problem_details(
        code, udm_protocol_application_error::USER_NOT_FOUND,
        problem_description, response_data);
    Logger::udm_ueau().warn(problem_description);
    return;
  }

  // UDR's URL
  std::string remote_uri =
      udm_sbi_helper::get_udr_session_management_subscription_data_uri(
          supi, plmn_id.value());
  std::string query_str = {};
  std::string body      = {};

  if (snssai.has_value() and snssai.value().getSst() > 0) {
    query_str +=
        "?single-nssai={\"sst\":" + std::to_string(snssai.value().getSst()) +
        ",\"sd\":\"" + snssai.value().getSd() + "\"}";
    if (dnn.has_value()) {
      query_str += "&dnn=" + dnn.value();
    }
  } else if (dnn.has_value()) {
    query_str += "?dnn=" + dnn.value();
  }

  // URI with Optional SNSSAI/DNN
  remote_uri += query_str;

  Logger::udm_sdm().debug("Remote URI: " + remote_uri);

  oai::http::request http_request =
      http_client_inst->prepare_json_request(remote_uri, body);
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::GET, http_request);
  code = http_response.status_code;

  Logger::udm_sdm().debug("HTTP response code %ld", code);

  // Process response
  try {
    Logger::udm_sdm().debug("Response: " + http_response.body);
    response_data = nlohmann::json::parse(http_response.body.c_str());
  } catch (nlohmann::json::exception& e) {
    Logger::udm_sdm().info("Could not get JSON content from UDR response");
    code = oai::common::sbi::http_status_code::NOT_FOUND;
    std::string problem_description = "User " + supi + " not found";
    set_problem_details(
        code, udm_protocol_application_error::USER_NOT_FOUND,
        problem_description, response_data);
    Logger::udm_ueau().warn(problem_description);
    return;
  }
  return;
}

//------------------------------------------------------------------------------
void udm_app::handle_slice_selection_subscription_data_retrieval(
    const std::string& supi, nlohmann::json& response_data, uint32_t& code,
    std::string supported_features, PlmnId plmn_id) {
  Logger::udm_sdm().debug(
      "Handle Slice Selection Subscription Data Retrieval request");

  // Get the corresponding UDR's URI
  std::string udr_uri =
      udm_sbi_helper::get_udr_slice_selection_subscription_data_retrieval_uri(
          supi, plmn_id);
  std::string body = {};
  Logger::udm_sdm().debug("Remote URI: %s", udr_uri.c_str());
  // Send the request and get the response from UDR
  oai::http::request http_request =
      http_client_inst->prepare_json_request(udr_uri, body);
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::GET, http_request);

  code = http_response.status_code;
  Logger::udm_sdm().debug("HTTP response code %d", http_response.status_code);
  Logger::udm_sdm().debug("Response from UDR: %s", http_response.body.c_str());

  // Process the response
  nlohmann::json return_response_data_json = {};
  try {
    return_response_data_json =
        nlohmann::json::parse(http_response.body.c_str());
    if (return_response_data_json.find("nssai") !=
        return_response_data_json.end()) {
      response_data = return_response_data_json["nssai"];
      Logger::udm_sdm().debug(
          "Slice Selection Subscription Data from UDR: %s",
          response_data.dump().c_str());
    }
  } catch (nlohmann::json::exception& e) {
    Logger::udm_sdm().info("Could not get JSON content from UDR's response");
    code = oai::common::sbi::http_status_code::NOT_FOUND;
    std::string problem_description =
        "Subscription with SUPI " + supi + " not found";
    set_problem_details(
        code, protocol_application_error::SUBSCRIPTION_NOT_FOUND,
        problem_description, response_data);
    Logger::udm_ueau().warn(problem_description);
    return;
  }
}

//------------------------------------------------------------------------------
void udm_app::handle_smf_selection_subscription_data_retrieval(
    const std::string& supi, nlohmann::json& response_data, uint32_t& code,
    std::string supported_features, PlmnId plmn_id) {
  // Get UDR's URI
  std::string remote_uri =
      udm_sbi_helper::get_udr_smf_selection_subscription_data_uri(
          supi, plmn_id);

  std::string body = {};
  Logger::udm_sdm().debug("Remote URI: " + remote_uri);

  // Get info from UDR
  oai::http::request http_request =
      http_client_inst->prepare_json_request(remote_uri, body);
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::GET, http_request);
  code = http_response.status_code;

  // Process response
  try {
    Logger::udm_sdm().debug(
        "subscription-data: GET Response: " + http_response.body);
    response_data = nlohmann::json::parse(http_response.body.c_str());
  } catch (nlohmann::json::exception& e) {
    Logger::udm_sdm().info("Could not get JSON content from UDR response");
    code = oai::common::sbi::http_status_code::NOT_FOUND;
    std::string problem_description = "User " + supi + " not found";
    set_problem_details(
        code, udm_protocol_application_error::USER_NOT_FOUND,
        problem_description, response_data);
    Logger::udm_ueau().warn(problem_description);
    return;
  }
  Logger::udm_sdm().debug("HTTP response code %d", code);
  return;
}

//------------------------------------------------------------------------------
void udm_app::handle_subscription_creation(
    const std::string& supi,
    const oai::_3gpp::model::SdmSubscription& sdmSubscription,
    nlohmann::json& response_data, uint32_t& code) {
  std::string udr_ip =
      std::string(inet_ntoa(*((struct in_addr*) &udm_cfg.udr_addr.ipv4_addr)));
  std::string udr_port = std::to_string(udm_cfg.udr_addr.port);
  std::string remote_uri;
  std::string msg_body;
  nlohmann::json problem_details_json;
  ProblemDetails problem_details;

  // Get 3gpp_registration related info
  remote_uri = udm_sbi_helper::get_udr_sdm_subscriptions_uri(supi);
  Logger::udm_uecm().debug("Remote URI:" + remote_uri);

  nlohmann::json sdm_subscription_json;
  to_json(sdm_subscription_json, sdmSubscription);

  oai::http::request http_request = http_client_inst->prepare_json_request(
      remote_uri, sdm_subscription_json.dump());
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::POST, http_request);

  nlohmann::json response_data_json = {};
  try {
    Logger::udm_uecm().debug("HTTP Response:" + http_response.body);
    response_data_json = nlohmann::json::parse(http_response.body.c_str());

  } catch (nlohmann::json::exception& e) {  // error handling
    Logger::udm_uecm().info("Could not get JSON content from UDR response");
    code = oai::common::sbi::http_status_code::NOT_FOUND;
    std::string problem_description = "User " + supi + " not found";
    set_problem_details(
        code, udm_protocol_application_error::USER_NOT_FOUND,
        problem_description, response_data);
    Logger::udm_ueau().warn(problem_description);
    return;
  }
  Logger::udm_uecm().debug("HTTP response code %d", http_response.status_code);
  response_data = sdm_subscription_json;  // to be verified
  code          = http_response.status_code;
}

//------------------------------------------------------------------------------
evsub_id_t udm_app::handle_create_ee_subscription(
    const std::string& ueIdentity,
    const oai::_3gpp::model::EeSubscription& eeSubscription,
    oai::_3gpp::model::CreatedEeSubscription& createdSub,
    oai::_3gpp::model::ProblemDetails& problemDetails, uint32_t& code) {
  Logger::udm_ee().info("Handle Create EE Subscription");

  // Validate mandatory IE: callbackReference must be present
  if (eeSubscription.getCallbackReference().empty()) {
    Logger::udm_ee().warn("EeSubscription is missing callbackReference");
    problemDetails.setStatus(oai::common::sbi::http_status_code::BAD_REQUEST);
    problemDetails.setCause(
        oai::common::sbi::protocol_application_error_to_string(
            oai::common::sbi::protocol_application_error::
                MANDATORY_IE_INCORRECT));
    problemDetails.setDetail("Missing mandatory IE: callbackReference");
    code = oai::common::sbi::http_status_code::BAD_REQUEST;
    return INVALID_EVSUB_ID;
  }

  // Generate a subscription ID Id and store the corresponding information in a
  // map (subscription id, info)
  evsub_id_t evsub_id = generate_ev_subscription_id();

  oai::_3gpp::model::EeSubscription es = eeSubscription;
  // TODO: Update Subscription

  // MonitoringConfiguration

  es.setSubscriptionId(std::to_string(evsub_id));
  std::shared_ptr<CreatedEeSubscription> ces =
      std::make_shared<CreatedEeSubscription>(createdSub);
  ces->setEeSubscription(es);

  if (!ueIdentity.empty()) {
    ces->setNumberOfUes(1);
  } else {
    // TODO: For group of UEs
  }
  // TODO: MonitoringReport

  add_event_subscription(evsub_id, ueIdentity, ces);
  // Return the created subscription in the response body
  createdSub = *ces;
  code       = oai::common::sbi::http_status_code::CREATED;

  // If at least one of the requested events is detected by the AMF, relay the
  // subscription to the AMF serving this UE. Events detected by the SMF or the
  // SMS-GMSC are only accepted and stored, they are not relayed yet.
  bool needs_amf_relay = false;
  for (const auto& kv : es.getMonitoringConfigurations()) {
    if (classify_event_detector(kv.second.getEventType().getEnumValue()) ==
        ee_event_detector_t::AMF_RELAY) {
      needs_amf_relay = true;
      break;
    }
  }
  if (needs_amf_relay && !ueIdentity.empty()) {
    evsub_id_t sid     = evsub_id;
    std::string ue_cpy = ueIdentity;
    relay_subscribe_to_amf(sid, ue_cpy);
  }

  return evsub_id;
}

//------------------------------------------------------------------------------
void udm_app::handle_delete_ee_subscription(
    const std::string& ueIdentity, const std::string& subscriptionId,
    ProblemDetails& problemDetails, uint32_t& code) {
  Logger::udm_ee().info("Handle Delete EE Subscription");

  if (!delete_event_subscription(subscriptionId, ueIdentity)) {
    // Set ProblemDetails. SUBSCRIPTION_NOT_FOUND belongs to the common causes
    // defined in TS 29.500, not to the UDM-specific ones defined in TS 29.503,
    // so the model is filled in directly here
    problemDetails.setStatus(oai::common::sbi::http_status_code::NOT_FOUND);
    problemDetails.setCause("SUBSCRIPTION_NOT_FOUND");
    problemDetails.setDetail(
        "EE subscription " + subscriptionId + " not found");
    code = oai::common::sbi::http_status_code::NOT_FOUND;
    return;
  }

  // Delete the corresponding subscription on the AMF, if there is one
  try {
    relay_unsubscribe(std::stoul(subscriptionId));
  } catch (std::exception&) {
  }

  code = oai::common::sbi::http_status_code::NO_CONTENT;
  return;
}

//------------------------------------------------------------------------------
void udm_app::handle_update_ee_subscription(
    const std::string& ueIdentity, const std::string& subscriptionId,
    const std::vector<PatchItem>& patchItem, ProblemDetails& problemDetails,
    uint32_t& code) {
  Logger::udm_ee().info("Handle Update EE Subscription");

  // Make sure that the subscription does exist
  {
    uint32_t sub_id = 0;
    try {
      sub_id = std::stoul(subscriptionId);
    } catch (std::exception& e) {
      sub_id = 0;
    }
    std::shared_lock lock(m_mutex_udm_event_subscriptions);
    if (sub_id == 0 || udm_event_subscriptions.count(sub_id) == 0) {
      Logger::udm_ee().warn(
          "EE subscription %s not found", subscriptionId.c_str());
      problemDetails.setStatus(oai::common::sbi::http_status_code::NOT_FOUND);
      problemDetails.setCause("SUBSCRIPTION_NOT_FOUND");
      problemDetails.setDetail(
          "EE subscription " + subscriptionId + " not found");
      code = oai::common::sbi::http_status_code::NOT_FOUND;
      return;
    }
  }

  for (auto p : patchItem) {
    auto op         = p.getOp().getEnumValue();
    bool op_success = true;
    // Verify Path
    if ((p.getPath().substr(0, 1).compare("/") != 0) or
        (p.getPath().length() < 2)) {
      Logger::udm_ee().warn(
          "Bad value for operation path: %s ", p.getPath().c_str());
      code = oai::common::sbi::http_status_code::BAD_REQUEST;
      problemDetails.setStatus(oai::common::sbi::http_status_code::BAD_REQUEST);
      problemDetails.setCause(
          oai::common::sbi::protocol_application_error_to_string(
              oai::common::sbi::protocol_application_error::
                  MANDATORY_IE_INCORRECT));
      return;
    }

    std::string path = p.getPath().substr(1);

    switch (op) {
      case PatchOperation_anyOf::ePatchOperation_anyOf::REPLACE: {
        op_success =
            replace_ee_subscription_item(subscriptionId, path, p.getValue());
      } break;

      case PatchOperation_anyOf::ePatchOperation_anyOf::ADD: {
        op_success =
            add_ee_subscription_item(subscriptionId, path, p.getValue());
      } break;

      case PatchOperation_anyOf::ePatchOperation_anyOf::REMOVE: {
        op_success = remove_ee_subscription_item(subscriptionId, path);
      } break;

      default: {
        Logger::udm_ee().warn("Requested operation is not valid!");
        op_success = false;
      }
    }

    if (!op_success) {
      code = oai::common::sbi::http_status_code::BAD_REQUEST;
      problemDetails.setStatus(oai::common::sbi::http_status_code::BAD_REQUEST);
      problemDetails.setCause(
          oai::common::sbi::protocol_application_error_to_string(
              oai::common::sbi::protocol_application_error::
                  INVALID_QUERY_PARAM));
      problemDetails.setDetail("Unsupported patch operation/path: " + path);
      return;
    }
  }

  // All the requested modifications have been applied
  code = oai::common::sbi::http_status_code::NO_CONTENT;
}

//------------------------------------------------------------------------------
evsub_id_t udm_app::generate_ev_subscription_id() {
  return evsub_id_generator.get_uid();
}

//------------------------------------------------------------------------------
void udm_app::add_event_subscription(
    const evsub_id_t& sub_id, const std::string& ue_id,
    std::shared_ptr<oai::_3gpp::model::CreatedEeSubscription>& ces) {
  std::unique_lock lock(m_mutex_udm_event_subscriptions);
  udm_event_subscriptions[sub_id] = ces;
  std::vector<evsub_id_t> ev_subs;

  if (udm_event_subscriptions_per_ue.count(ue_id) > 0) {
    ev_subs = udm_event_subscriptions_per_ue.at(ue_id);
  }
  ev_subs.push_back(sub_id);
  udm_event_subscriptions_per_ue[ue_id] = ev_subs;
  return;
}

//------------------------------------------------------------------------------
bool udm_app::delete_event_subscription(
    const std::string& subscription_id, const std::string& ue_id) {
  std::unique_lock lock(m_mutex_udm_event_subscriptions);
  bool result     = true;
  uint32_t sub_id = 0;
  try {
    sub_id = std::stoul(subscription_id);
  } catch (std::exception e) {
    Logger::udm_ee().warn(
        "Bad value for subscription id %s ", subscription_id.c_str());
    return false;
  }

  // The removal is successful only if the subscription did exist
  if (udm_event_subscriptions.count(sub_id)) {
    udm_event_subscriptions.erase(sub_id);
  } else {
    result = false;
  }

  // Remove this subscription from the list of subscriptions of the UE, and
  // forget the UE once it has no subscription left
  if (udm_event_subscriptions_per_ue.count(ue_id) > 0) {
    std::vector<evsub_id_t>& ev_subs = udm_event_subscriptions_per_ue.at(ue_id);
    ev_subs.erase(
        std::remove(ev_subs.begin(), ev_subs.end(), sub_id), ev_subs.end());
    if (ev_subs.empty()) {
      udm_event_subscriptions_per_ue.erase(ue_id);
    }
  }

  return result;
}

//------------------------------------------------------------------------------
bool udm_app::replace_ee_subscription_item(
    const std::string& subscriptionId, const std::string& path,
    const std::string& value) {
  Logger::udm_ee().debug(
      "Replace member %s with new value %s (subscription %s)", path.c_str(),
      value.c_str(), subscriptionId.c_str());

  uint32_t sub_id = 0;
  try {
    sub_id = std::stoul(subscriptionId);
  } catch (std::exception& e) {
    return false;
  }

  std::unique_lock lock(m_mutex_udm_event_subscriptions);
  if (udm_event_subscriptions.count(sub_id) == 0) return false;
  std::shared_ptr<CreatedEeSubscription>& ces = udm_event_subscriptions[sub_id];
  if (!ces) return false;

  EeSubscription es = ces->getEeSubscription();
  if (path.compare("callbackReference") == 0) {
    es.setCallbackReference(value);
  } else if (path.compare("notifyCorrelationId") == 0) {
    es.setNotifyCorrelationId(value);
  } else if (path.compare("secondCallbackRef") == 0) {
    es.setSecondCallbackRef(value);
  } else {
    // Any other member cannot be replaced
    return false;
  }
  ces->setEeSubscription(es);
  return true;
}

//------------------------------------------------------------------------------
bool udm_app::add_ee_subscription_item(
    const std::string& subscriptionId, const std::string& path,
    const std::string& value) {
  Logger::udm_ee().debug(
      "Add member %s with value %s (subscription %s)", path.c_str(),
      value.c_str(), subscriptionId.c_str());

  uint32_t sub_id = 0;
  try {
    sub_id = std::stoul(subscriptionId);
  } catch (std::exception& e) {
    return false;
  }

  std::unique_lock lock(m_mutex_udm_event_subscriptions);
  if (udm_event_subscriptions.count(sub_id) == 0) return false;
  std::shared_ptr<CreatedEeSubscription>& ces = udm_event_subscriptions[sub_id];
  if (!ces) return false;

  EeSubscription es = ces->getEeSubscription();
  if (path.compare("includeGpsiList") == 0) {
    std::vector<std::string> list = es.getIncludeGpsiList();
    list.push_back(value);
    es.setIncludeGpsiList(list);
  } else if (path.compare("excludeGpsiList") == 0) {
    std::vector<std::string> list = es.getExcludeGpsiList();
    list.push_back(value);
    es.setExcludeGpsiList(list);
  } else {
    return false;
  }
  ces->setEeSubscription(es);
  return true;
}

//------------------------------------------------------------------------------
bool udm_app::remove_ee_subscription_item(
    const std::string& subscriptionId, const std::string& path) {
  Logger::udm_ee().debug(
      "Remove member %s (subscription %s)", path.c_str(),
      subscriptionId.c_str());

  uint32_t sub_id = 0;
  try {
    sub_id = std::stoul(subscriptionId);
  } catch (std::exception& e) {
    return false;
  }

  std::unique_lock lock(m_mutex_udm_event_subscriptions);
  if (udm_event_subscriptions.count(sub_id) == 0) return false;
  std::shared_ptr<CreatedEeSubscription>& ces = udm_event_subscriptions[sub_id];
  if (!ces) return false;

  EeSubscription es = ces->getEeSubscription();
  if (path.compare("includeGpsiList") == 0) {
    es.unsetIncludeGpsiList();
  } else if (path.compare("excludeGpsiList") == 0) {
    es.unsetExcludeGpsiList();
  } else {
    return false;
  }
  ces->setEeSubscription(es);
  return true;
}

//------------------------------------------------------------------------------
void udm_app::notify_event_occurrence(
    const std::string& callback_uri,
    const std::vector<oai::_3gpp::model::MonitoringReport>& reports) {
  if (callback_uri.empty() || reports.empty()) return;

  // The body of an Event Occurrence notification is a list of
  // Monitoring Reports
  nlohmann::json body = nlohmann::json::array();
  for (const auto& r : reports) {
    nlohmann::json j = {};
    to_json(j, r);
    body.push_back(j);
  }

  Logger::udm_ee().info(
      "Notify event occurrence (%zu report(s)) to %s", reports.size(),
      callback_uri.c_str());

  oai::http::request http_request =
      http_client_inst->prepare_json_request(callback_uri, body.dump());

  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::POST, http_request);

  if (http_response.status_code !=
      oai::common::sbi::http_status_code::NO_CONTENT) {
    Logger::udm_ee().warn(
        "Event notification to %s returned HTTP %d", callback_uri.c_str(),
        http_response.status_code);
  }
}

//------------------------------------------------------------------------------
ee_event_detector_t udm_app::classify_event_detector(
    EventType_anyOf::eEventType_anyOf ev) const {
  using E = EventType_anyOf::eEventType_anyOf;
  switch (ev) {
    case E::UE_REACHABILITY_FOR_SMS:
    case E::CHANGE_OF_SUPI_PEI_ASSOCIATION:
    case E::ROAMING_STATUS:
    case E::CN_TYPE_CHANGE:
      return ee_event_detector_t::UDM_LOCAL;
    case E::AVAILABILITY_AFTER_DDN_FAILURE:
    case E::DL_DATA_DELIVERY_STATUS:
    case E::PDN_CONNECTIVITY_STATUS:
    case E::PDU_SES_REL:
    case E::PDU_SES_EST:
      return ee_event_detector_t::SMF_RELAY;
    case E::UE_MEMORY_AVAILABLE_FOR_SMS:
      return ee_event_detector_t::SMS_GMSC;
    case E::INVALID_VALUE_OPENAPI_GENERATED:
      return ee_event_detector_t::UNKNOWN;
    default:
      // All the remaining events are detected by the AMF:
      // LOSS_OF_CONNECTIVITY, UE_REACHABILITY_FOR_DATA, LOCATION_REPORTING,
      // COMMUNICATION_FAILURE, UE_CONNECTION_MANAGEMENT_STATE,
      // ACCESS_TYPE_REPORT, REGISTRATION_STATE_REPORT,
      // CONNECTIVITY_STATE_REPORT, TYPE_ALLOCATION_CODE_REPORT,
      // FREQUENT_MOBILITY_REGISTRATION_REPORT
      return ee_event_detector_t::AMF_RELAY;
  }
}

//------------------------------------------------------------------------------
std::string udm_app::namf_event_type_for(
    EventType_anyOf::eEventType_anyOf ev) const {
  using E = EventType_anyOf::eEventType_anyOf;
  switch (ev) {
    case E::LOSS_OF_CONNECTIVITY:
      return "LOSS_OF_CONNECTIVITY";
    case E::UE_REACHABILITY_FOR_DATA:
      return "REACHABILITY_REPORT";
    case E::LOCATION_REPORTING:
      return "LOCATION_REPORT";
    case E::COMMUNICATION_FAILURE:
      return "COMMUNICATION_FAILURE_REPORT";
    case E::UE_CONNECTION_MANAGEMENT_STATE:
    case E::CONNECTIVITY_STATE_REPORT:
      return "CONNECTIVITY_STATE_REPORT";
    case E::ACCESS_TYPE_REPORT:
      return "ACCESS_TYPE_REPORT";
    case E::REGISTRATION_STATE_REPORT:
      return "REGISTRATION_STATE_REPORT";
    case E::TYPE_ALLOCATION_CODE_REPORT:
      return "TYPE_ALLOCATION_CODE_REPORT";
    case E::FREQUENT_MOBILITY_REGISTRATION_REPORT:
      return "FREQUENT_MOBILITY_REGISTRATION_REPORT";
    default:
      return std::string{};
  }
}

//------------------------------------------------------------------------------
std::string udm_app::get_serving_amf_instance_id(const std::string& ue_id) {
  std::string remote_uri =
      udm_sbi_helper::get_udr_amf_3gpp_registration_uri(ue_id);
  oai::http::request req = http_client_inst->prepare_json_request(remote_uri);
  auto resp =
      http_client_inst->send_http_request(oai::common::sbi::method_e::GET, req);
  if (resp.status_code != oai::common::sbi::http_status_code::OK) {
    Logger::udm_ee().warn(
        "Could not read AMF registration for %s from UDR (HTTP %d)",
        ue_id.c_str(), resp.status_code);
    return std::string{};
  }
  try {
    nlohmann::json reg = nlohmann::json::parse(resp.body);
    return reg.value("amfInstanceId", std::string{});
  } catch (nlohmann::json::exception&) {
    return std::string{};
  }
}

//------------------------------------------------------------------------------
void udm_app::relay_subscribe_to_amf(
    const evsub_id_t& sub_id, const std::string& ue_id) {
  // Get the events detected by the AMF and the consumer's callback info from
  // this subscription
  std::string callback;
  std::string notify_correlation_id;
  std::vector<std::string> amf_event_types;
  {
    std::shared_lock lock(m_mutex_udm_event_subscriptions);
    auto it = udm_event_subscriptions.find(sub_id);
    if (it == udm_event_subscriptions.end() || !it->second) return;
    EeSubscription es     = it->second->getEeSubscription();
    callback              = es.getCallbackReference();
    notify_correlation_id = es.getNotifyCorrelationId();
    for (const auto& kv : es.getMonitoringConfigurations()) {
      auto ev = kv.second.getEventType().getEnumValue();
      if (classify_event_detector(ev) == ee_event_detector_t::AMF_RELAY) {
        std::string t = namf_event_type_for(ev);
        if (!t.empty()) amf_event_types.push_back(t);
      }
    }
  }
  if (amf_event_types.empty() || callback.empty()) return;

  // Find the AMF serving this UE: its instance ID comes from the UDR, its
  // address from the NRF
  std::string amf_instance_id = get_serving_amf_instance_id(ue_id);
  std::string amf_endpoint;
  if (!udm_nrf_inst ||
      !udm_nrf_inst->discover_nf("AMF", "namf-evts", amf_endpoint)) {
    Logger::udm_ee().warn(
        "AMF relay for sub %u: could not discover serving AMF", sub_id);
    return;
  }

  // Build the body of the AmfCreateEventSubscription request. The consumer's
  // callback and correlation ID are forwarded as they are, so that the AMF
  // sends the notifications directly to the consumer
  nlohmann::json sub = {};
  sub["eventList"]   = nlohmann::json::array();
  for (const auto& t : amf_event_types) {
    nlohmann::json e = {};
    e["type"]        = t;
    sub["eventList"].push_back(e);
  }
  sub["eventNotifyUri"] = callback;
  if (!notify_correlation_id.empty())
    sub["notifyCorrelationId"] = notify_correlation_id;
  sub["nfId"]          = m_udm_instance_id;
  nlohmann::json body  = {};
  body["subscription"] = sub;

  std::string amf_subscriptions_uri =
      amf_endpoint + oai::common::sbi::sbi_helper::AmfEvtsBase + "v1" +
      oai::common::sbi::sbi_helper::AmfEvtsPathSubscriptions;

  Logger::udm_ee().info(
      "AMF relay for sub %u -> %s", sub_id, amf_subscriptions_uri.c_str());

  oai::http::request http_request = http_client_inst->prepare_json_request(
      amf_subscriptions_uri, body.dump());
  auto resp = http_client_inst->send_http_request(
      oai::common::sbi::method_e::POST, http_request);

  if (resp.status_code != oai::common::sbi::http_status_code::CREATED) {
    Logger::udm_ee().warn(
        "AMF relay subscribe for sub %u failed (HTTP %d)", sub_id,
        resp.status_code);
    return;
  }
  std::string remote_uri;
  auto loc = resp.headers.find("location");
  if (loc != resp.headers.end()) remote_uri = loc->second;

  relay_correlation_t corr     = {};
  corr.remote_nf_type          = "AMF";
  corr.remote_subscription_uri = remote_uri;
  corr.amf_instance_id         = amf_instance_id;
  {
    std::unique_lock lock(m_mutex_udm_event_subscriptions);
    udm_event_relay_correlation[sub_id] = corr;
  }
  Logger::udm_ee().info(
      "AMF relay for sub %u stored (remote %s)", sub_id, remote_uri.c_str());
}

//------------------------------------------------------------------------------
void udm_app::relay_unsubscribe(const evsub_id_t& sub_id) {
  std::string remote_uri;
  {
    std::unique_lock lock(m_mutex_udm_event_subscriptions);
    auto it = udm_event_relay_correlation.find(sub_id);
    if (it == udm_event_relay_correlation.end()) return;
    remote_uri = it->second.remote_subscription_uri;
    udm_event_relay_correlation.erase(it);
  }

  oai::http::request http_request =
      http_client_inst->prepare_json_request(remote_uri);
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::DELETE, http_request);

  if (http_response.status_code !=
      oai::common::sbi::http_status_code::NO_CONTENT) {
    Logger::udm_ee().warn(
        "AMF relay unsubscribe to %s returned HTTP %d", remote_uri.c_str(),
        http_response.status_code);
  }
}

//------------------------------------------------------------------------------
void udm_app::send_revocation(
    const evsub_id_t& sub_id,
    const oai::_3gpp::model::EeMonitoringRevoked& revoked) {
  std::string second_callback;
  {
    std::shared_lock lock(m_mutex_udm_event_subscriptions);
    auto it = udm_event_subscriptions.find(sub_id);
    if (it == udm_event_subscriptions.end() || !it->second) return;
    second_callback = it->second->getEeSubscription().getSecondCallbackRef();
  }
  if (second_callback.empty()) {
    Logger::udm_ee().warn(
        "Revocation for sub %u: no secondCallbackRef set", sub_id);
    return;
  }

  nlohmann::json body = {};
  to_json(body, revoked);
  Logger::udm_ee().info(
      "Send monitoring revocation for sub %u -> %s", sub_id,
      second_callback.c_str());

  oai::http::request http_request =
      http_client_inst->prepare_json_request(second_callback, body.dump());
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::POST, http_request);

  if (http_response.status_code !=
      oai::common::sbi::http_status_code::NO_CONTENT) {
    Logger::udm_ee().warn(
        "Revocation to %s returned HTTP %d", second_callback.c_str(),
        http_response.status_code);
  }
}

//------------------------------------------------------------------------------
void udm_app::send_data_restoration(
    const oai::_3gpp::model::DataRestorationNotification& notification) {
  // Notify every subscription that provided a dataRestorationCallbackUri
  std::vector<std::string> uris;
  {
    std::shared_lock lock(m_mutex_udm_event_subscriptions);
    for (const auto& kv : udm_event_subscriptions) {
      if (!kv.second) continue;
      std::string uri =
          kv.second->getEeSubscription().getDataRestorationCallbackUri();
      if (!uri.empty()) uris.push_back(uri);
    }
  }
  if (uris.empty()) return;

  nlohmann::json body = {};
  to_json(body, notification);
  const std::string payload = body.dump();

  for (const auto& uri : uris) {
    Logger::udm_ee().info(
        "Send data restoration notification -> %s", uri.c_str());

    oai::http::request http_request =
        http_client_inst->prepare_json_request(uri, payload);
    auto http_response = http_client_inst->send_http_request(
        oai::common::sbi::method_e::POST, http_request);

    if (http_response.status_code !=
        oai::common::sbi::http_status_code::NO_CONTENT) {
      Logger::udm_ee().warn(
          "Data restoration to %s returned HTTP %d", uri.c_str(),
          http_response.status_code);
    }
  }
}

//------------------------------------------------------------------------------
void udm_app::handle_ee_loss_of_connectivity(
    const std::string& ue_id, uint8_t status, uint8_t http_version) {
  // TODO:
}

//------------------------------------------------------------------------------
void udm_app::handle_ee_ue_reachability_for_data(
    const std::string& ue_id, uint8_t status, uint8_t http_version) {
  // TODO:
}

//------------------------------------------------------------------------------
void udm_app::increment_sqn(const std::string& c_sqn, std::string& n_sqn) {
  unsigned long long sqn_value;
  std::stringstream s1;
  s1 << std::hex << c_sqn;
  s1 >> sqn_value;  // hex string to decimal value
  sqn_value += 32;
  std::stringstream s2;
  s2 << std::hex << std::setw(12) << std::setfill('0')
     << sqn_value;  // decimal value to hex string

  std::string sqn_tmp(s2.str());
  n_sqn = sqn_tmp;
}

//------------------------------------------------------------------------------
void udm_app::set_problem_details(
    uint16_t status, uint16_t cause, const std::string& detail,
    nlohmann::json& problem_details) {
  ProblemDetails p = {};
  p.setStatus(status);
  p.setCause(udm_protocol_application_error_to_string(cause));
  p.setDetail(detail);
  to_json(problem_details, p);
}

//------------------------------------------------------------------------------
void udm_app::get_hplmn_id(
    const std::string& supi,
    std::optional<oai::_3gpp::model::PlmnId>& plmn_id) {
  std::shared_lock lh(m_mutex_hplmn);

  if (hplmn.count(supi) > 0) {
    plmn_id = std::make_optional<oai::_3gpp::model::PlmnId>(hplmn.at(supi));
  }
  lh.unlock();
  return;
}

//------------------------------------------------------------------------------
void udm_app::store_plmn_id(
    const std::string& supi, const oai::_3gpp::model::PlmnId& plmn_id) {
  std::unique_lock lh(m_mutex_hplmn);
  hplmn[supi] = plmn_id;
  lh.unlock();
  return;
}

//------------------------------------------------------------------------------
bool udm_app::validate_snn(
    const std::string& snn, oai::_3gpp::model::PlmnId& plmn_id) {
  // example of SNN: 5G:mnc095.mcc208.3gppnetwork.org
  std::string regex_str = "^5G:mnc[0-9]{3}[.]mcc[0-9]{3}[.]3gppnetwork[.]org$";
  try {
    std::regex re(regex_str);
    if (!std::regex_match(snn, re)) {
      Logger::udm_app().debug(
          "SNN (%s) does not follow the regex specification (%s)", snn,
          regex_str);
      return false;
    }
  } catch (const std::regex_error& e) {
    Logger::udm_app().warn("regex_error caught %s", e.what());
    return false;
  }

  std::vector<std::string> split_str;
  boost::split(split_str, snn, boost::is_any_of("."));
  if (split_str.size() != 4) return false;
  if (split_str[0].size() == 9)
    plmn_id.setMnc(split_str[0].substr(6, 3));
  else
    return false;
  if (split_str[1].size() == 6)
    plmn_id.setMcc(split_str[1].substr(3, 3));
  else
    return false;

  return true;
}
