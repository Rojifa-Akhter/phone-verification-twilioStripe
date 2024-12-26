<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Twilio\Rest\Client;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    public function register(Request $request)
{
    // Validate input
    $validator = Validator::make($request->all(), [
        'name' => 'required|string|max:255',
        'phone' => 'required|string|max:255',
        'password' => 'required|string|min:6',
    ]);

    if ($validator->fails()) {
        return response()->json(['status' => false, 'message' => $validator->errors()], 400);
    }

    // Format phone number to E.164 format (add country code if missing)
    $phone = $request->phone;
    if (substr($phone, 0, 1) == '0') {
        // Assuming country code is +880 (Bangladesh). Adjust according to your country.
        $phone = '+880' . substr($phone, 1);
    }

    // Generate OTP
    $otp = rand(1000, 9999);

    // Save user with OTP (you can store OTP and OTP expiration time here)
    $user = User::create([
        'name' => $request->name,
        'phone' => $phone,  // Store the correctly formatted phone number
        'password' => Hash::make($request->password),
        'otp' => $otp,
        'otp_expires_at' => now()->addMinutes(10), // OTP expiry time
    ]);

    // Send OTP via Twilio
    try {
        $twilio = new Client(env('TWILIO_SID'), env('TWILIO_TOKEN'));
        $twilio->messages->create(
            $phone, // Use the formatted phone number
            [
                'from' => env('TWILIO_PHONE_NUMBER'),
                'body' => 'Your OTP code is: ' . $otp,
            ]
        );
    } catch (\Twilio\Exceptions\RestException $e) {
        return response()->json(['status' => false, 'message' => 'Twilio Error: ' . $e->getMessage()], 400);
    }

    return response()->json([
        'status' => true,
        'message' => 'User registered successfully. Please verify your phone number using the OTP sent to your phone.',
    ], 201);
}


    public function login(Request $request)
    {
        // Validate input
        $validator = Validator::make($request->all(), [
            'phone' => 'required|string',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['status' => false, 'message' => $validator->errors()], 400);
        }

        // Find user by phone
        $user = User::where('phone', $request->phone)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json(['status' => false, 'message' => 'Invalid credentials.'], 401);
        }

        // Generate JWT token
        $token = JWTAuth::fromUser($user);

        return response()->json([
            'status' => true,
            'token' => $token,
            'message' => 'Login successful.',
        ], 200);
    }

    public function verifyOtp(Request $request)
    {
        // Validate input
        $validator = Validator::make($request->all(), [
            'phone' => 'required|string',
            'otp' => 'required|numeric',
        ]);

        if ($validator->fails()) {
            return response()->json(['status' => false, 'message' => $validator->errors()], 400);
        }

        // Find user by phone and check OTP validity
        $user = User::where('phone', $request->phone)->first();

        if (!$user || $user->otp !== $request->otp || $user->otp_expires_at < now()) {
            return response()->json(['status' => false, 'message' => 'Invalid or expired OTP.'], 400);
        }

        // Mark user as active and update OTP
        $user->status = 'active';
        $user->otp = null;
        $user->otp_expires_at = null;
        $user->save();

        return response()->json([
            'status' => true,
            'message' => 'Phone number verified successfully.',
        ], 200);
    }
}
