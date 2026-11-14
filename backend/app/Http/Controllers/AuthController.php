<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Models\Log;
use App\Traits\ApiResponse;
use App\Services\AuthenticationService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\DB;

class AuthController extends Controller
{
    use ApiResponse;

    protected AuthenticationService $authService;

    /**
     * Create a new controller instance.
     */
    public function __construct(AuthenticationService $authService)
    {
        $this->authService = $authService;
    }

    // ✅ REGISTER
    public function register(Request $request)
    {
        $validated = $request->validate([
            'name'     => 'required|string|max:255',
            'email'    => 'required|email|unique:users,email',
            'password' => 'required|string|min:8|confirmed',
        ]);

        $user = User::create([
            'name'     => $validated['name'],
            'email'    => $validated['email'],
            'password' => Hash::make($validated['password']),
        ]);

        $token = $user->createToken('it-asset-token')->plainTextToken;

        // ✅ LOG REGISTER — pakai tabel logs (konsisten dengan controller lain)
        Log::create([
            'user_id'     => $user->id,
            'activity'    => 'register',
            'description' => "User baru '{$user->name}' berhasil registrasi",
            'ip_address'  => $request->ip(),
            'user_agent'  => $request->userAgent(),
        ]);

        return $this->createdResponse([
            'user'  => $user,
            'token' => $token,
        ], 'Registrasi berhasil');
    }

    // // ✅ LOGIN
    // public function login(Request $request)
    // {
    //     $request->validate([
    //         'email'    => 'required|email',
    //         'password' => 'required',
    //     ]);

    //     $result = $this->authService->authenticate(
    //         $request->email,
    //         $request->password,
    //         'it-asset-token',
    //         'frontend',
    //         $request->ip(),
    //         $request->userAgent()
    //     );

    //     if (!$result['success']) {
    //         return $this->errorResponse($result['message'], 401);
    //     }

    //     return $this->successResponse([
    //         'user'  => $result['user'],
    //         'token' => $result['token'],
    //     ], 'Login berhasil');
    // }

    // LOGIN + AUTO REGISTER
public function login(Request $request)
{
    $request->validate([
        'email'    => 'required|email',
        'password' => 'required|string',
    ]);

    // Cek apakah user sudah terdaftar
    $user = User::where('email', $request->email)->first();

    // Jika belum terdaftar, lakukan auto register
    if (!$user) {

        // Format email harus 4 digit@gmail.com
        if (!preg_match('/^(\d{4})@gmail\.com$/i', $request->email, $matches)) {
            return $this->errorResponse(
                'Email belum terdaftar dan harus menggunakan format 4 digit@gmail.com',
                401
            );
        }

        $fourDigit = $matches[1];

        // Password default = 4 digit + 4 digit
        $defaultPassword = $fourDigit . $fourDigit;

        // Validasi password default
        if ($request->password !== $defaultPassword) {
            return $this->errorResponse(
                'Password untuk registrasi otomatis tidak sesuai',
                401
            );
        }

        // Buat user baru
        $user = DB::transaction(function () use ($fourDigit, $request, $defaultPassword) {

            return User::firstOrCreate(
                ['email' => $request->email],
                [
                    'name'     => $fourDigit,
                    'password' => Hash::make($defaultPassword),
                ]
            );
        });
    }

    // Proses autentikasi
    $result = $this->authService->authenticate(
        $request->email,
        $request->password,
        'it-asset-token',
        'frontend',
        $request->ip(),
        $request->userAgent()
    );

    if (!$result['success']) {
        return $this->errorResponse($result['message'], 401);
    }

    return $this->successResponse([
        'user'  => $result['user'],
        'token' => $result['token'],
    ], 'Login berhasil');
}

    // ✅ LOGOUT
    public function logout(Request $request)
    {
        $user = $request->user();

        // ✅ LOG LOGOUT — pakai tabel logs
        Log::create([
            'user_id'     => $user->id,
            'activity'    => 'logout',
            'description' => "User '{$user->name}' berhasil logout",
            'ip_address'  => $request->ip(),
            'user_agent'  => $request->userAgent(),
        ]);

        $request->user()->currentAccessToken()->delete();

        return $this->successResponse(null, 'Logout berhasil');
    }

    // ✅ GET PROFILE
    public function me(Request $request)
    {
        return $this->successResponse($request->user(), 'Data user berhasil diambil');
    }
}