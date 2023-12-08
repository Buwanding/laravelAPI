namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    protected $model;

    public function __construct()
    {
        $this->model = new User();
    }
  
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string|min:6', 
        ]);

        try {
            $credentials = $request->only('email', 'password');

            if (!Auth::attempt($credentials)) {
                return response(['message' => "Invalid credentials"], 401);
            } 

            $user = $this->model->where('email', $request->email)->first();            
            $token = $user->createToken($request->email . Str::random(8))->plainTextToken;

            return response(['token' => $token], 200);

        } catch (\Exception $e) {
            return response(['message' => $e->getMessage()], 400);
        }
    }

    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|string|confirmed|min:6', 
        ]);

        try {
            $data = $request->all();
            $data['password'] = Hash::make($data['password']); // Hash the password

            $this->model->create($data);

            return response(['message' => "Successfully created"], 201);
        } catch (\Exception $e) {
            return response(['message' => $e->getMessage()], 400);
        }
    }
}
