// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { Suspense, lazy } from 'react'
import { Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { AnimatePresence, motion } from 'framer-motion'
import { useAuthStore } from './state/authStore'
import { pageTransition } from './styles/animations'
import Callback from './pages/Callback'
import RealmPicker from './pages/RealmPicker'
import AppLayout from './components/layout/AppLayout'
import RealmContextGuard from './components/layout/RealmContextGuard'
import PageLoader from './components/ui/PageLoader'
import { CONFIG } from './config'

const DashboardPage = lazy(() => import('./pages/dashboard/DashboardPage'))
const RealmListPage = lazy(() => import('./pages/realms/RealmListPage'))
const RealmEditPage = lazy(() => import('./pages/realms/RealmEditPage'))
const RealmSettingsPage = lazy(() => import('./pages/realms/RealmSettingsPage'))
const UserListPage = lazy(() => import('./pages/users/UserListPage'))
const UserDetailPage = lazy(() => import('./pages/users/UserDetailPage'))
const ClientListPage = lazy(() => import('./pages/clients/ClientListPage'))
const ClientEditPage = lazy(() => import('./pages/clients/ClientEditPage'))
const ClientScopeListPage = lazy(() => import('./pages/client-scopes/ClientScopeListPage'))
const ClientScopeDetailPage = lazy(() => import('./pages/client-scopes/ClientScopeDetailPage'))
const RoleListPage = lazy(() => import('./pages/roles/RoleListPage'))
const RoleEditPage = lazy(() => import('./pages/roles/RoleEditPage'))
const GroupListPage = lazy(() => import('./pages/groups/GroupListPage'))
const GroupEditPage = lazy(() => import('./pages/groups/GroupEditPage'))
const SessionListPage = lazy(() => import('./pages/sessions/SessionListPage'))
const EventListPage = lazy(() => import('./pages/events/EventListPage'))
const IdPListPage = lazy(() => import('./pages/identity-providers/IdPListPage'))
const IdPEditPage = lazy(() => import('./pages/identity-providers/IdPEditPage'))
const KeysPage = lazy(() => import('./pages/keys/KeysPage'))
const AuthFlowListPage = lazy(() => import('./pages/auth-flows/AuthFlowListPage'))
const AuthFlowDetailPage = lazy(() => import('./pages/auth-flows/AuthFlowDetailPage'))
const ServerInfoPage = lazy(() => import('./pages/server-info/ServerInfoPage'))
const SecurityDashboard = lazy(() => import('./pages/security/SecurityDashboard'))
const NotFoundPage = lazy(() => import('./pages/NotFoundPage'))

function LoginRedirect() {
  window.location.href = '/login.html'
  return null
}

function AnimatedOutlet() {
  const location = useLocation()
  return (
    <AnimatePresence mode="wait">
      <motion.div
        key={location.pathname}
        variants={pageTransition}
        initial="hidden"
        animate="visible"
        exit="exit"
        className="h-full"
      >
        <Suspense fallback={<PageLoader />}>
          <Routes location={location}>
            <Route index element={<Navigate to="dashboard" replace />} />
            <Route path="dashboard" element={<DashboardPage />} />
            <Route path="realms" element={<RealmListPage />} />
            <Route path="realms/:realm/edit" element={<RealmEditPage />} />
            <Route path="realms/:realm/settings" element={<RealmSettingsPage />} />
            <Route path="users" element={<UserListPage />} />
            <Route path="users/:id" element={<UserDetailPage />} />
            <Route path="clients" element={<ClientListPage />} />
            <Route path="clients/:id" element={<ClientEditPage />} />
            <Route path="client-scopes" element={<ClientScopeListPage />} />
            <Route path="client-scopes/:id" element={<ClientScopeDetailPage />} />
            <Route path="roles" element={<RoleListPage />} />
            <Route path="roles/:name" element={<RoleEditPage />} />
            <Route path="groups" element={<GroupListPage />} />
            <Route path="groups/:id" element={<GroupEditPage />} />
            <Route path="sessions" element={<SessionListPage />} />
            <Route path="events" element={<EventListPage />} />
            <Route path="identity-providers" element={<IdPListPage />} />
            <Route path="identity-providers/:alias" element={<IdPEditPage />} />
            <Route path="keys" element={<KeysPage />} />
            <Route path="auth-flows" element={<AuthFlowListPage />} />
            <Route path="auth-flows/:alias" element={<AuthFlowDetailPage />} />
            <Route path="server-info" element={<ServerInfoPage />} />
            <Route path="security" element={<SecurityDashboard />} />
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </Suspense>
      </motion.div>
    </AnimatePresence>
  )
}

function App() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated(CONFIG.REALM))

  return (
    <Routes>
      <Route path="/" element={isAuthenticated ? <Navigate to="/realm-picker" replace /> : <LoginRedirect />} />
      <Route path="/callback" element={<Callback />} />
      <Route path="/realm-picker" element={<RealmPicker />} />
      <Route
        path="/*"
        element={
          <RealmContextGuard>
            <AppLayout />
          </RealmContextGuard>
        }
      >
        <Route path="*" element={<AnimatedOutlet />} />
      </Route>
    </Routes>
  )
}

export default App
