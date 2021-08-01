<?php

namespace App\Controller;

use App\Entity\Users;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use App\Repository\UsersRepository;
use DateTime;
use Symfony\Component\HttpFoundation\Exception\BadRequestException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class AuthController extends AbstractController
{
    private $passwordpasswordHasher;

    public function __construct(UserPasswordHasherInterface  $passwordHasher) {
        $this->passwordpasswordHasher = $passwordHasher;
    }

    #[Route('/api/signin', name: 'signin', methods: ['POST'])]
    public function index(AuthenticationUtils $authenticationUtils): Response
    {
        $error = $authenticationUtils->getLastAuthenticationError();
        $lastUsername = $authenticationUtils->getLastUsername();
        return $this->json([
            'message' => 'Welcome to your new controller!',
            'path' => 'src/Controller/AuthController.php',
        ]);
    }

    #[Route('/api/signup', name: 'signup', methods:['POST'])]
    public function create(Request $request, UsersRepository $repo) {

        $params = json_decode($request->getContent(), true);
        $users = $this->buildSignupData($params);

        // check if the login already exists
        $isLoginExists = $repo->isLoginExist($users->getLogin());
        $isMailUsed = $repo->isMailUsed($users->getMail());

        if(!empty($isLoginExists)) {
            throw new BadRequestException('Le login existe déja, veuillez choisir un autre', 455);
        }

        if(!empty($isMailUsed)) {
            throw new BadRequestException('Le mail est déja utilisé', 455);
        }


        $repo->add($users);
        //TODO add sending e-mail to verify that it's a real user not a robot
        return $this->json([
            'data' => 'the signup succeed'
        ]); 
    }

    /**
     * TODO add mor esecurity on building data
     */
    private function buildSignupData(Array $params) : Users {
        $users = new Users();
        //$users->setRole('USER');
        $users->setValidFrom(new DateTime('now'));

        if( isset($params['login']) && trim($params['login']) !== '') {
            $users->setLogin(trim($params['login']));
        }

        if(isset($params['mail']) && trim($params['mail'])!=='' && preg_match("/^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/", trim($params['mail']))) {
            $users->setMail(trim($params['mail']));
        }

        if( isset($params['lastname']) && trim($params['lastname']) !== '') {
            $users->setLastname(trim($params['lastname']));
        }

        if( isset($params['firstname']) && trim($params['firstname']) !== '') {
            $users->setName(trim($params['firstname']));
        }

        $pwd = trim($params['pwd']);
        $repwd = trim($params['repwd']);
        

        if($pwd!==null && $pwd === $repwd) {
            $users->setPassword($this->passwordHasher->hashPassword($users, $pwd));
        } else {
            throw new BadRequestException('Mot de passe différents');
        }

        if(!$users->isValid()) {
            throw new BadRequestException('problème de donnée d\'entrée');
        }

        return $users;
    }

    #[Route('/api/signout', name: 'logout', methods: ['GET'])]
    public function logout(Request $request): Response {

        return $this->json([
            'data' => 'the signout succeed'
        ]); 
    }
}
