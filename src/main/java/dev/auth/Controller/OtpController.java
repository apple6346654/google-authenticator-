package dev.auth.Controller;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OtpController {

    // 메모리 내에 OTP 키 저장하기 위한 맵 (실제 서비스에서는 Redis 같은 캐시를 사용할 수 있음)
    private Map<String, String> otpKeyStorage = new ConcurrentHashMap<>();

    // GET 요청으로 OTP 생성
    @GetMapping("/otp")
    public Map<String, String> generateOtp() {
        // 랜덤 바이트 배열 생성
        byte[] buffer = new byte[5 + 5 * 5];
        new Random().nextBytes(buffer);

        // Base32 인코딩으로 키 변환
        Base32 codec = new Base32();
        byte[] secretKey = Arrays.copyOf(buffer, 5 + 5 * 5);  // SecretKey는 5바이트로 잘라서 사용
        byte[] bEncodedKey = codec.encode(secretKey);

        // 생성된 OTP Key
        String encodedKey = new String(bEncodedKey);

        System.out.println("encodedKey : " + encodedKey);

        // 테스트용 userName과 hostName
        String url = getQRBarcodeURL("hj", "company.com", encodedKey);
        System.out.println("URL : " + url);

        // OTP Key를 사용자 ID "hj"로 저장
        otpKeyStorage.put("hj", encodedKey);

        // 결과 반환 (URL 및 OTP 키)
        Map<String, String> response = new HashMap<>();
        response.put("encodedKey", encodedKey);
        response.put("url", url);

        return response;
    }

    // POST 요청으로 OTP 입력 검증 (user와 otp를 @RequestParam으로 받음)
    @PostMapping("/otp/verify")
    public Map<String, String> verifyOtp(@RequestParam String user, @RequestParam String otp) {
        // 저장된 OTP 키 가져오기
        String storedKey = otpKeyStorage.get(user);

        Map<String, String> response = new HashMap<>();
        if (storedKey != null) {
            // 현재 시간 기준으로 OTP 검증
            long currentTimeMillis = new Date().getTime();
            long timeWindow = currentTimeMillis / 30000;  // 30초 단위로 시간 창 생성

            try {
                boolean isValid = checkCode(storedKey, Long.parseLong(otp), timeWindow);
                if (isValid) {
                    response.put("status", "success");
                    response.put("message", "OTP 검증 성공");
                } else {
                    response.put("status", "failure");
                    response.put("message", "OTP 검증 실패");
                }
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                e.printStackTrace();
                response.put("status", "error");
                response.put("message", "OTP 검증 중 오류 발생");
            }
        } else {
            response.put("status", "failure");
            response.put("message", "유저에 대한 OTP 정보가 없습니다");
        }

        return response;
    }

    // OTP 검증 메서드
    private static boolean checkCode(String secret, long code, long t) throws NoSuchAlgorithmException, InvalidKeyException {
        Base32 codec = new Base32();
        byte[] decodedKey = codec.decode(secret);

        // 코드 검증을 위한 시간 창 (과거/미래 3개 확인)
        int window = 0;
        for (int i = -window; i <= window; ++i) {
            long hash = verifyCode(decodedKey, t + i);

            if (hash == code) {
                return true;
            }
        }
        return false;
    }

    // OTP 해시 계산 메서드
    private static int verifyCode(byte[] key, long t) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] data = new byte[8];
        long value = t;
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }

        SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signKey);
        byte[] hash = mac.doFinal(data);

        int offset = hash[20 - 1] & 0xF;

        long truncatedHash = 0;
        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;
            truncatedHash |= (hash[offset + i] & 0xFF);
        }

        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= 1000000;

        return (int) truncatedHash;
    }

    // QR 코드 URL 생성 메서드
    private static String getQRBarcodeURL(String user, String host, String secret) {
        String format = "https://chart.googleapis.com/chart?cht=qr&chs=300x300&chl=otpauth://totp/%s@%s%%3Fsecret%%3D%s&chld=H|0";
        return String.format(format, user, host, secret);
    }
}