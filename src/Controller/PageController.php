<?php

declare(strict_types=1);

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Les pages ne demandent rien à la base : un lien /s/<id> s'affiche pareil qu'il existe ou
 * non, et c'est le navigateur qui interroge l'API quand on clique. Un robot d'aperçu qui
 * ouvre le lien ne consomme donc rien.
 */
final class PageController extends AbstractController
{
    private const string ID = '[A-Za-z0-9_-]{22}';

    #[Route('/', name: 'home', methods: ['GET'])]
    public function home(): Response
    {
        return $this->render('pages/home.html.twig');
    }

    #[Route('/request', name: 'request_new', methods: ['GET'])]
    public function requestNew(): Response
    {
        return $this->render('pages/request_new.html.twig');
    }

    #[Route('/s/{id}', name: 'secret_reveal', requirements: ['id' => self::ID], methods: ['GET'])]
    public function reveal(): Response
    {
        return $this->render('pages/reveal.html.twig');
    }

    #[Route('/m/{id}', name: 'secret_manage', requirements: ['id' => self::ID], methods: ['GET'])]
    public function manage(): Response
    {
        return $this->render('pages/manage.html.twig');
    }

    #[Route('/r/{id}', name: 'request_respond', requirements: ['id' => self::ID], methods: ['GET'])]
    public function respond(): Response
    {
        return $this->render('pages/respond.html.twig');
    }

    #[Route('/i/{id}', name: 'request_inbox', requirements: ['id' => self::ID], methods: ['GET'])]
    public function inbox(): Response
    {
        return $this->render('pages/inbox.html.twig');
    }

    #[Route('/security', name: 'security', methods: ['GET'])]
    public function security(): Response
    {
        return $this->render('pages/security.html.twig');
    }

    #[Route('/privacy', name: 'privacy', methods: ['GET'])]
    public function privacy(): Response
    {
        return $this->render('pages/privacy.html.twig');
    }

    #[Route('/terms', name: 'terms', methods: ['GET'])]
    public function terms(): Response
    {
        return $this->render('pages/terms.html.twig');
    }
}
