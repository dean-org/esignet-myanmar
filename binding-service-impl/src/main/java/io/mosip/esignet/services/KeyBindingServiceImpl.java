/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.esignet.services;

import static io.mosip.esignet.api.util.ErrorConstants.SEND_OTP_FAILED;
import static io.mosip.esignet.core.constants.Constants.UTC_DATETIME_PATTERN;
import static io.mosip.esignet.core.constants.ErrorConstants.*;

import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.esignet.api.dto.AuthChallenge;
import io.mosip.esignet.api.dto.KeyBindingResult;
import io.mosip.esignet.api.dto.SendOtpResult;
import io.mosip.esignet.api.exception.KeyBindingException;
import io.mosip.esignet.api.exception.SendOtpException;
import io.mosip.esignet.api.spi.KeyBinder;
import io.mosip.esignet.core.dto.BindingOtpRequest;
import io.mosip.esignet.core.dto.BindingOtpResponse;
import io.mosip.esignet.core.dto.WalletBindingRequest;
import io.mosip.esignet.core.dto.WalletBindingResponse;
import io.mosip.esignet.core.exception.EsignetException;
import io.mosip.esignet.core.spi.KeyBindingService;
import io.mosip.esignet.entity.PublicKeyRegistry;
import io.mosip.esignet.repository.PublicKeyRegistryRepository;
import io.mosip.kernel.keymanagerservice.util.KeymanagerUtil;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.lang.JoseException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@Transactional
public class KeyBindingServiceImpl implements KeyBindingService {

    @Autowired
    private KeyBinder keyBindingWrapper;

    @Autowired
    private PublicKeyRegistryRepository publicKeyRegistryRepository;

    @Autowired
    private KeymanagerUtil keymanagerUtil;

    @Autowired
    private KeyBindingHelperService keyBindingHelperService;

    @Autowired
    private ObjectMapper objectMapper;

    @Value("${mosip.esignet.binding.encrypt-binding-id:true}")
    private boolean encryptBindingId;

    @Override
    public BindingOtpResponse sendBindingOtp(
            BindingOtpRequest bindingOtpRequest,
            Map<String, String> requestHeaders) throws EsignetException {

        log.debug("sendBindingOtp :: Request headers >> {}", requestHeaders);

        SendOtpResult sendOtpResult;
        try {
            sendOtpResult = keyBindingWrapper.sendBindingOtp(
                    bindingOtpRequest.getIndividualId(),
                    bindingOtpRequest.getOtpChannels(),
                    requestHeaders);
        } catch (SendOtpException e) {
            log.error("Failed to send binding OTP", e);
            throw new EsignetException(e.getErrorCode());
        }

        if (sendOtpResult == null) {
            log.error("send-otp failed: wrapper returned null result");
            throw new EsignetException(SEND_OTP_FAILED);
        }

        BindingOtpResponse response = new BindingOtpResponse();
        response.setMaskedEmail(sendOtpResult.getMaskedEmail());
        response.setMaskedMobile(sendOtpResult.getMaskedMobile());
        return response;
    }

    private void validateChallengeListAuthFormat(
            List<AuthChallenge> challengeList) {

        if (!challengeList.stream().allMatch(challenge ->
                keyBindingWrapper
                        .getSupportedChallengeFormats(challenge.getAuthFactorType())
                        .contains(challenge.getFormat()))) {
            log.error("Invalid auth factor type or challenge format");
            throw new EsignetException(
                    INVALID_AUTH_FACTOR_TYPE_OR_CHALLENGE_FORMAT);
        }
    }

    @Override
    public WalletBindingResponse bindWallet(
            WalletBindingRequest walletBindingRequest,
            Map<String, String> requestHeaders) throws EsignetException {

        log.debug("bindWallet :: Request headers >> {}", requestHeaders);

        validateChallengeListAuthFormat(
                walletBindingRequest.getChallengeList());

        if (!keyBindingWrapper
                .getSupportedChallengeFormats(
                        walletBindingRequest.getAuthFactorType())
                .contains(walletBindingRequest.getFormat())) {
            throw new EsignetException(
                    INVALID_AUTH_FACTOR_TYPE_OR_CHALLENGE_FORMAT);
        }

        Map<String, Object> publicKey =
                walletBindingRequest.getPublicKey();

        KeyBindingResult keyBindingResult;
        try {
            keyBindingResult = keyBindingWrapper.doKeyBinding(
                    walletBindingRequest.getIndividualId(),
                    walletBindingRequest.getChallengeList(),
                    publicKey,
                    walletBindingRequest.getAuthFactorType(),
                    requestHeaders);
        } catch (KeyBindingException e) {
            log.error("Failed to bind the key", e);
            throw new EsignetException(e.getErrorCode());
        }

        if (keyBindingResult == null
                || keyBindingResult.getCertificate() == null
                || keyBindingResult.getPartnerSpecificUserToken() == null) {
            log.error("Wallet binding failed: {}", keyBindingResult);
            throw new EsignetException(KEY_BINDING_FAILED);
        }

        /*
         * Serialize the public key for registry storage if the helper's
         * method accepts a String. If it accepts Map<String, Object>,
         * pass publicKey directly instead.
         */
        String publicKeyJson;
        try {
            publicKeyJson = objectMapper.writeValueAsString(publicKey);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize public key", e);
            throw new EsignetException(KEY_BINDING_FAILED);
        }

        PublicKeyRegistry publicKeyRegistry =
                keyBindingHelperService.storeKeyBindingDetailsInRegistry(
                        walletBindingRequest.getIndividualId(),
                        keyBindingResult.getPartnerSpecificUserToken(),
                        publicKeyJson,
                        keyBindingResult.getCertificate(),
                        walletBindingRequest.getAuthFactorType());

        String bindingId = publicKeyRegistry.getWalletBindingId();

        if (encryptBindingId) {
            bindingId = getJWE(publicKey, bindingId);
        }

        return new WalletBindingResponse(
                bindingId,
                keyBindingResult.getCertificate(),
                publicKeyRegistry.getExpiredtimes().format(
                        DateTimeFormatter.ofPattern(UTC_DATETIME_PATTERN)));
    }

    private String getJWE(
            Map<String, Object> publicKey,
            String walletBindingId) {

        try {
            RsaJsonWebKey jsonWebKey = new RsaJsonWebKey(publicKey);

            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setAlgorithmHeaderValue(
                    KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
            jwe.setEncryptionMethodHeaderParameter(
                    ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
            jwe.setPayload(walletBindingId);
            jwe.setContentTypeHeaderValue("JWT");
            jwe.setKey(jsonWebKey.getKey());
            jwe.setKeyIdHeaderValue(jsonWebKey.getKeyId());

            return jwe.getCompactSerialization();

        } catch (JoseException e) {
            log.error("Failed to create JWE", e);
            throw new EsignetException(FAILED_TO_CREATE_JWE);
        }
    }
}
